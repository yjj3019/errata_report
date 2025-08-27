# Red Hat Errata 페이지의 보안 권고를 스크래핑하고, JSON으로 데이터를 관리하며, AI로 요약하는 스크립트입니다.
# 실행 전, 필요한 라이브러리를 설치해야 합니다.
# 터미널에서 아래 명령어를 실행하세요:
# pip install requests beautifulsoup4

import requests
from bs4 import BeautifulSoup
import csv
import datetime
import time
import json
import os

# --- AI 요약 함수 (사용자 정의 필요) ---
def summarize_with_llm(text):
    """
    주어진 텍스트를 로컬 LLM을 사용하여 요약합니다.
    !!! 중요: 이 함수는 사용자의 로컬 LLM 환경에 맞게 직접 구현해야 합니다. !!!
    
    예시 (Ollama API 사용 시):
    try:
        import ollama
        response = ollama.chat(model='llama3', messages=[
            {
                'role': 'user',
                'content': f"다음 Red Hat 보안 권고 요약문을 한국어로 한 문장으로 요약해줘: {text}",
            },
        ])
        return response['message']['content']
    except Exception as e:
        print(f"  [AI 요약 오류] LLM 호출에 실패했습니다: {e}")
        return "AI 요약 실패"
    """
    # 현재는 원본 텍스트를 그대로 반환하는 플레이스홀더입니다.
    print("  [AI 요약] 로컬 LLM 호출 시뮬레이션...")
    return f"[AI 요약 필요] {text}"

def get_cve_details(detail_url):
    """
    각 보안 권고의 상세 페이지로 이동하여 CVE ID 목록을 추출합니다.
    """
    try:
        response = requests.get(detail_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        cve_links = soup.select("a[href*='/security/cve/CVE-']")
        if not cve_links:
            return "CVE 정보 없음"
        cve_ids = [link.text.strip() for link in cve_links]
        return ", ".join(sorted(list(set(cve_ids))))
    except requests.exceptions.RequestException as e:
        print(f"  [오류] 상세 페이지 접근 실패: {detail_url} - {e}")
        return "상세 확인 실패"

def load_existing_data(filename):
    """
    기존에 저장된 JSON 데이터를 불러옵니다. 파일이 없거나 형식이 잘못된 경우를 처리합니다.
    """
    if os.path.exists(filename):
        print(f"'{filename}'에서 기존 데이터를 불러옵니다.")
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    print(f"  [정보] 데이터 형식이 리스트입니다. 딕셔너리로 변환합니다.")
                    return {item['errata_id']: item for item in data if 'errata_id' in item}
                if not isinstance(data, dict):
                    print(f"  [경고] '{filename}'의 형식이 올바르지 않습니다. 새 데이터를 생성합니다.")
                    return {}
                return data
        except (json.JSONDecodeError, IOError) as e:
            print(f"  [경고] '{filename}' 파일을 읽는 중 오류가 발생했습니다: {e}. 새 데이터를 생성합니다.")
            return {}
    return {}

def save_data_to_json(data, filename):
    """
    데이터를 JSON 파일로 저장합니다.
    """
    print(f"'{filename}'에 업데이트된 데이터를 저장합니다.")
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

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
            writer.writerow(['권고 ID', 'CVE ID', '심각도', '게시일', '영향받는 제품', 'AI 요약'])
            for item in sorted_data:
                writer.writerow([
                    item['errata_id'],
                    item['cve_id'],
                    item['severity'],
                    item['issue_date'],
                    item['affected_products'],
                    item['summary']
                ])
        print(f"성공적으로 '{filename}' 파일에 최신 보고서를 저장했습니다.")
    except IOError as e:
        print(f"오류: CSV 파일을 저장할 수 없습니다. - {e}")

def scrape_redhat_errata():
    """
    Red Hat Errata를 스크래핑하고, JSON 데이터와 중복 체크 후 AI 요약을 추가하여 저장합니다.
    """
    json_filename = "cve_data.json"
    base_url = "https://access.redhat.com"
    
    current_year = datetime.datetime.now().year
    print(f"정보: 현재 연도({current_year})를 기준으로 데이터를 검색합니다.")
    
    params = {
        'q': '', 'p': '1', 'sort': 'portal_update_date desc', 'rows': '1000',
        'portal_publication_date': str(current_year),
        'portal_product': 'Red Hat Enterprise Linux'
    }
    search_url = f"{base_url}/errata-search/"

    existing_data = load_existing_data(json_filename)
    existing_ids = set(existing_data.keys())
    print(f"현재 {len(existing_ids)}개의 데이터가 저장되어 있습니다.")

    print(f"\n'{search_url}'에서 새 데이터 스크래핑을 시작합니다...")
    try:
        response = requests.get(search_url, params=params, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"오류: 웹 페이지에 접근할 수 없습니다. - {e}")
        return

    soup = BeautifulSoup(response.content, 'html.parser')
    
    # --- 디버깅 기능 강화 ---
    # 로그인 페이지나 접근 거부 페이지로 리디렉션되었는지 확인
    page_title = soup.title.string if soup.title else ""
    if "Login" in page_title or "Access Denied" in page_title:
        print("경고: 로그인 페이지 또는 접근 거부 페이지로 리디렉션되었습니다. IP가 차단되었거나 로그인이 필요할 수 있습니다.")
        debug_filename = "debug_page.html"
        with open(debug_filename, 'w', encoding='utf-8') as f:
            f.write(soup.prettify())
        print(f"현재 페이지의 HTML을 '{debug_filename}' 파일로 저장했습니다. 내용을 확인해주세요.")
        return

    rows = soup.select('div.rh-search-result__row')

    if not rows:
        print("경고: 스크래핑할 데이터를 찾을 수 없습니다. 검색 결과가 없거나 웹사이트 구조가 변경되었을 수 있습니다.")
        # 디버깅을 위해 현재 페이지의 HTML을 파일로 저장
        debug_filename = "debug_page.html"
        with open(debug_filename, 'w', encoding='utf-8') as f:
            f.write(soup.prettify())
        print(f"\n>>> 현재 페이지의 전체 HTML을 '{debug_filename}' 파일로 저장했습니다. <<<")
        print("이 파일을 열어 데이터 목록을 감싸는 HTML 태그와 클래스 이름을 확인하고,")
        print("스크립트의 'rows = soup.select(...)' 부분을 새로운 값으로 수정해보세요.")
        return

    print(f"총 {len(rows)}개의 항목을 찾았습니다. 중복을 확인하고 신규 항목을 처리합니다.")
    new_items_count = 0

    for i, row in enumerate(rows):
        cells = row.select('div.rh-search-result__cell')
        if len(cells) < 5: continue

        try:
            errata_link_tag = cells[0].find('a')
            if not errata_link_tag: continue
            errata_id = errata_link_tag.text.strip()

            if errata_id in existing_ids:
                continue

            new_items_count += 1
            print(f"\n[{i+1}/{len(rows)}] 새로운 항목 '{errata_id}' 발견. 처리 시작...")
            
            detail_page_url = base_url + errata_link_tag['href']
            synopsis = cells[1].text.strip()
            
            cve_id = get_cve_details(detail_page_url)
            summary = summarize_with_llm(synopsis)
            
            existing_data[errata_id] = {
                'errata_id': errata_id,
                'cve_id': cve_id,
                'severity': cells[3].find('span').text.strip() if cells[3].find('span') else 'N/A',
                'issue_date': cells[2].text.strip(),
                'affected_products': "Red Hat Enterprise Linux",
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


if __name__ == "__main__":
    scrape_redhat_errata()
