# Red Hat Errata 페이지의 보안 권고를 스크래핑하고, JSON으로 데이터를 관리하며, AI로 요약하는 스크립트입니다.
# [수정] 동적 콘텐츠 로딩 문제 해결을 위해 Selenium을 사용합니다.
#
# 실행 전, 필요한 라이브러리를 설치해야 합니다.
# 터미널에서 아래 명령어를 실행하세요:
# pip install requests beautifulsoup4 selenium webdriver-manager

import requests
from bs4 import BeautifulSoup
import csv
import datetime
import time
import json
import os
import argparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# --- AI 요약 함수 (명령줄 인수로 받은 API 정보 사용) ---
def summarize_with_llm(text, llm_url, api_token, model):
    """
    주어진 텍스트를 외부 LLM API를 사용하여 요약합니다.
    """
    if not llm_url or not api_token or not model:
        return f"[AI 요약 생략] {text}"

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    data = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a helpful assistant that summarizes security advisories into a single, concise Korean sentence."},
            {"role": "user", "content": f"다음 Red Hat 보안 권고 요약문을 한국어로 한 문장으로 요약해줘: {text}"}
        ],
        "max_tokens": 1024,
        "temperature": 0.7
    }
    
    print("  [AI 요약] LLM API 호출 중...")
    try:
        response = requests.post(llm_url, headers=headers, json=data, timeout=60)
        response.raise_for_status()
        result = response.json()
        summary = result.get('choices', [{}])[0].get('message', {}).get('content', 'AI 요약 실패: 응답 형식 불일치')
        return summary.strip()
    except requests.exceptions.RequestException as e:
        print(f"  [AI 요약 오류] LLM API 호출에 실패했습니다: {e}")
    except (KeyError, IndexError) as e:
        print(f"  [AI 요약 오류] 예상치 못한 API 응답 구조입니다: {e} - 응답: {response.text}")
    return "AI 요약 실패"


def get_cve_details(detail_url):
    """
    각 보안 권고의 상세 페이지로 이동하여 CVE ID 목록을 추출합니다.
    """
    try:
        response = requests.get(detail_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        cve_section = soup.find('section', id='cves')
        if cve_section:
            cve_links = cve_section.select("a[href*='/security/cve/CVE-']")
            if cve_links:
                cve_ids = [link.text.strip() for link in cve_links]
                return ", ".join(sorted(list(set(cve_ids))))
        return "CVE 정보 없음"
    except requests.exceptions.RequestException as e:
        print(f"  [오류] 상세 페이지 접근 실패: {detail_url} - {e}")
        return "상세 확인 실패"

def load_existing_data(filename):
    """
    기존에 저장된 JSON 데이터를 불러옵니다.
    """
    if os.path.exists(filename):
        print(f"'{filename}'에서 기존 데이터를 불러옵니다.")
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    print(f"  [정보] 데이터 형식이 리스트입니다. 딕셔너리로 변환합니다.")
                    return {item['errata_id']: item for item in data if 'errata_id' in item}
                return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_data_to_json(data, filename):
    """
    데이터를 JSON 파일로 저장합니다.
    """
    print(f"'{filename}'에 업데이트된 데이터를 저장합니다.")
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(list(data.values()), f, ensure_ascii=False, indent=4)

def save_data_to_csv(data, filename):
    """
    데이터를 CSV 파일로 저장합니다.
    """
    if not data:
        print("CSV로 저장할 데이터가 없습니다.")
        return
        
    sorted_data = sorted(data.values(), key=lambda x: x['issue_date'], reverse=True)
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8-sig') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['권고 ID', 'CVE ID', '심각도', '게시일', '요약', 'AI 요약'])
            for item in sorted_data:
                writer.writerow([
                    item['errata_id'], item['cve_id'], item['severity'],
                    item['issue_date'], item['original_synopsis'], item['summary']
                ])
        print(f"성공적으로 '{filename}' 파일에 최신 보고서를 저장했습니다.")
    except IOError as e:
        print(f"오류: CSV 파일을 저장할 수 없습니다. - {e}")

def scrape_redhat_errata(llm_url, api_token, model, driver_path, year, no_headless):
    """
    [수정] Selenium을 사용하여 Red Hat Errata를 스크래핑하고, JSON 데이터와 중복 체크 후 AI 요약을 추가하여 저장합니다.
    """
    json_filename = "cve_data.json"
    base_url = "https://access.redhat.com"
    
    if year:
        target_year = year
    else:
        target_year = datetime.datetime.now().year
    print(f"정보: {target_year}년 데이터를 기준으로 검색합니다.")
    
    params = {
        'q': '', 'p': '1', 'sort': 'portal_update_date desc', 'rows': '1000',
        'portal_publication_date': str(target_year),
        'portal_product': 'Red\\ Hat\\ Enterprise\\ Linux'
    }
    search_url = f"{base_url}/errata-search/"

    existing_data = load_existing_data(json_filename)
    existing_ids = set(existing_data.keys())
    print(f"현재 {len(existing_ids)}개의 데이터가 저장되어 있습니다.")

    print(f"\n'{search_url}'에서 새 데이터 스크래핑을 시작합니다 (Selenium 사용)...")

    options = webdriver.ChromeOptions()
    if not no_headless:
        print("Headless 모드로 실행합니다.")
        options.add_argument('--headless')
    else:
        print("GUI 모드(no-headless)로 실행합니다.")
        
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--disable-extensions')
    options.add_argument('--disable-infobars')
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)
    
    options.add_argument('--window-size=1920,1080')
    options.add_argument("--log-level=3")
    options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')

    driver = None
    try:
        if driver_path:
            print(f"사용자 지정 ChromeDriver 경로를 사용합니다: {driver_path}")
            service = Service(executable_path=driver_path)
            driver = webdriver.Chrome(service=service, options=options)
            print("WebDriver가 성공적으로 초기화되었습니다.")
        else:
            print("WebDriver 자동 다운로드 및 초기화를 시도합니다...")
            driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
            print("WebDriver가 성공적으로 초기화되었습니다.")

        full_url = requests.Request('GET', search_url, params=params).prepare().url
        print(f"접속 URL: {full_url}")
        driver.get(full_url)
        wait = WebDriverWait(driver, 20)

        try:
            print("쿠키 동의 배너를 확인합니다...")
            cookie_iframe_xpath = "//iframe[contains(@title, 'TrustArc Cookie Consent Manager')]"
            cookie_iframe = wait.until(EC.presence_of_element_located((By.XPATH, cookie_iframe_xpath)))
            driver.switch_to.frame(cookie_iframe)
            print("쿠키 iFrame으로 전환했습니다.")

            agree_button_xpath = "//a[contains(text(), 'Agree and proceed with standard settings')]"
            agree_button = wait.until(EC.element_to_be_clickable((By.XPATH, agree_button_xpath)))
            
            driver.execute_script("arguments[0].click();", agree_button)
            print("쿠키 동의 버튼('Agree and proceed...')을 클릭했습니다.")
            
            driver.switch_to.default_content()
            print("메인 문서로 다시 전환했습니다.")
            
            # --- [핵심 수정] 페이지 안정화를 위한 강제 대기 시간 추가 ---
            print("페이지 전체 로딩을 위해 15초간 대기합니다...")
            time.sleep(15)

        except Exception:
            print("쿠키 동의 배너를 처리하지 못했습니다 (이미 동의했거나, 구조가 변경되었을 수 있습니다). 계속 진행합니다.")
            try:
                driver.switch_to.default_content()
            except:
                pass

        print("데이터 테이블을 확인합니다...")
        soup = BeautifulSoup(driver.page_source, 'html.parser')
        rows = soup.select('table.rh-table > tbody > tr')

        if not rows:
            print("경고: 스크래핑할 데이터를 찾을 수 없습니다. (Selenium 실행 후)")
            debug_filename = "debug_page_selenium.html"
            with open(debug_filename, 'w', encoding='utf-8') as f:
                f.write(soup.prettify())
            print(f"Selenium이 렌더링한 HTML을 '{debug_filename}' 파일로 저장했습니다.")
            return

        print(f"총 {len(rows)}개의 항목을 찾았습니다. 중복을 확인하고 신규 항목을 처리합니다.")
        new_items_count = 0

        for row in rows:
            cells = row.find_all('td')
            if len(cells) < 5: continue

            try:
                errata_link_tag = cells[0].find('a')
                if not errata_link_tag: continue
                errata_id = errata_link_tag.text.strip()

                if errata_id in existing_ids:
                    continue

                new_items_count += 1
                print(f"\n[{new_items_count}] 새로운 항목 '{errata_id}' 발견. 처리 시작...")
                
                detail_page_url = base_url + errata_link_tag['href']
                synopsis = cells[1].text.strip()
                
                cve_id = get_cve_details(detail_page_url)
                summary = summarize_with_llm(synopsis, llm_url, api_token, model)
                
                existing_data[errata_id] = {
                    'errata_id': errata_id,
                    'cve_id': cve_id,
                    'severity': cells[3].text.strip(),
                    'issue_date': cells[2].text.strip(),
                    'original_synopsis': synopsis,
                    'summary': summary
                }
                time.sleep(0.5)
            except Exception as e:
                print(f"  [오류] 데이터 추출 중 예외 발생: {e}")

        if new_items_count > 0:
            print(f"\n총 {new_items_count}개의 새로운 항목을 추가했습니다.")
            save_data_to_json(existing_data, json_filename)
        else:
            print("\n새로운 항목이 없습니다.")

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = f"redhat_errata_report_{timestamp}.csv"
        save_data_to_csv(existing_data, csv_filename)

    except Exception as e:
        print(f"오류: Selenium으로 페이지를 로드/처리하는 중 문제가 발생했습니다. - {e}")
        if driver:
            driver.save_screenshot('debug_screenshot.png')
            print("'debug_screenshot.png' 파일로 현재 화면을 저장했습니다.")
        return
    finally:
        if driver:
            print("WebDriver를 종료합니다.")
            driver.quit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Red Hat Errata 스크래퍼 및 AI 요약기")
    parser.add_argument('--llm-url', type=str, help='LLM API 엔드포인트 URL')
    parser.add_argument('--api-token', type=str, help='LLM API 인증 토큰')
    parser.add_argument('--model', type=str, help='사용할 LLM 모델 이름')
    parser.add_argument('--driver-path', type=str, help='로컬에 직접 다운로드한 ChromeDriver 실행 파일의 경로')
    parser.add_argument('--year', type=int, help='데이터를 검색할 연도 (기본값: 현재 연도)')
    parser.add_argument('--no-headless', action='store_true', help='이 플래그를 사용하면 브라우저 GUI가 표시됩니다.')
    args = parser.parse_args()

    scrape_redhat_errata(args.llm_url, args.api_token, args.model, args.driver_path, args.year, args.no_headless)
