#!/usr/bin/env python3
"""
Trivy Security Report Generator
Trivy 스캔 결과를 파싱하고 AI 기반 종합 보안 보고서를 생성합니다.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

def parse_sarif_file(file_path: str) -> Dict:
    """SARIF 파일을 파싱하고 취약점 정보를 추출합니다."""
    if not os.path.exists(file_path):
        return {"error": "파일을 찾을 수 없습니다"}
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        results = []
        severity_counts = {"error": 0, "warning": 0, "note": 0, "none": 0}
        
        for run in data.get("runs", []):
            for result in run.get("results", []):
                severity = result.get("level", "none")
                severity_counts[severity] += 1
                
                results.append({
                    "message": result.get("message", {}).get("text", "설명 없음"),
                    "severity": severity,
                    "location": result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "알 수 없음"),
                    "rule_id": result.get("ruleId", "알 수 없음")
                })
        
        return {
            "total_vulnerabilities": len(results),
            "severity_distribution": severity_counts,
            "all_vulnerabilities": results  # 모든 취약점 포함
        }
    except Exception as e:
        return {"error": f"SARIF 파일 파싱 실패: {str(e)}"}

def generate_ai_report(trivy_fs_results: Dict, trivy_iac_results: Dict) -> str:
    """AI 기반 보안 보고서를 생성합니다."""
    
    # 전체 통계 계산
    total_vulns = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    
    # 파일 시스템 스캔 결과
    if "error" not in trivy_fs_results:
        total_vulns += trivy_fs_results.get("total_vulnerabilities", 0)
        severity_dist = trivy_fs_results.get("severity_distribution", {})
        total_high += severity_dist.get("error", 0)
        total_medium += severity_dist.get("warning", 0)
        total_low += severity_dist.get("note", 0)
    
    # IaC 스캔 결과
    if "error" not in trivy_iac_results:
        total_vulns += trivy_iac_results.get("total_vulnerabilities", 0)
        severity_dist = trivy_iac_results.get("severity_distribution", {})
        total_high += severity_dist.get("error", 0)
        total_medium += severity_dist.get("warning", 0)
        total_low += severity_dist.get("note", 0)
    
    # AI 분석 및 권장사항 생성
    ai_analysis = generate_ai_analysis(total_high, total_medium, total_low, trivy_fs_results, trivy_iac_results)
    
    report = f"""# 🤖 AI 보안 스캔 보고서

## 📅 스캔 정보
- **스캔 날짜**: {datetime.now().strftime('%Y년 %m월 %d일 %H:%M:%S')}
- **브랜치**: {os.environ.get('GITHUB_REF', '알 수 없음')}
- **커밋**: {os.environ.get('GITHUB_SHA', '알 수 없음')[:8]}
- **저장소**: {os.environ.get('GITHUB_REPOSITORY', '알 수 없음')}

## 🔍 Trivy 스캔 결과 요약

### 📊 전체 통계
- **총 취약점 수**: {total_vulns}개
- **높은 심각도**: {total_high}개
- **중간 심각도**: {total_medium}개
- **낮은 심각도**: {total_low}개

### 🛠️ 스캔 도구별 결과

#### 🔍 Trivy 파일 시스템 스캔
"""
    
    if "error" in trivy_fs_results:
        report += f"- **상태**: ❌ {trivy_fs_results['error']}\n"
    else:
        vulns = trivy_fs_results.get("total_vulnerabilities", 0)
        severity_dist = trivy_fs_results.get("severity_distribution", {})
        report += f"- **상태**: ✅ 완료\n"
        report += f"- **발견된 취약점**: {vulns}개\n"
        report += f"- **심각도 분포**: 높음: {severity_dist.get('error', 0)}, 중간: {severity_dist.get('warning', 0)}, 낮음: {severity_dist.get('note', 0)}\n"
    
    report += "\n#### 🏗️ Trivy 인프라스트럭처 코드 스캔\n"
    
    if "error" in trivy_iac_results:
        report += f"- **상태**: ❌ {trivy_iac_results['error']}\n"
    else:
        vulns = trivy_iac_results.get("total_vulnerabilities", 0)
        severity_dist = trivy_iac_results.get("severity_distribution", {})
        report += f"- **상태**: ✅ 완료\n"
        report += f"- **발견된 취약점**: {vulns}개\n"
        report += f"- **심각도 분포**: 높음: {severity_dist.get('error', 0)}, 중간: {severity_dist.get('warning', 0)}, 낮음: {severity_dist.get('note', 0)}\n"
    
    # AI 분석 결과 추가
    report += f"\n## 🤖 AI 보안 분석\n\n{ai_analysis}\n"
    
    # 전체 상태
    overall_status = "✅ 통과" if total_high == 0 else "❌ 실패"
    report += f"""
## 🚨 보안 상태
- **전체 상태**: {overall_status}

## 📊 결과 위치
- **GitHub Security 탭**: 상세 취약점 보고서 보기
- **SARIF 파일**: 외부 분석을 위한 다운로드
- **아티팩트**: 상세 보고서는 워크플로우 아티팩트 확인

## 📋 다음 단계
1. GitHub Security 탭에서 결과 검토
2. 중요하거나 높은 심각도 문제 해결
3. 취약점이 발견된 경우 의존성 업데이트
4. 인프라 보안 권장사항 검토

---
*이 보고서는 Trivy 보안 스캔 파이프라인에 의해 자동으로 생성되었습니다.*
"""

    return report

def generate_ai_analysis(high_count: int, medium_count: int, low_count: int, 
                        trivy_fs: Dict, trivy_iac: Dict) -> str:
    """AI 기반 보안 분석 및 권장사항을 생성합니다."""
    
    analysis = ""
    
    # 전체 위험도 평가
    if high_count == 0 and medium_count == 0:
        analysis += "### 🟢 보안 상태: 양호\n"
        analysis += "현재 프로젝트의 보안 상태는 양호합니다. 발견된 취약점이 없거나 모두 낮은 심각도입니다.\n\n"
    elif high_count > 0:
        analysis += "### 🔴 보안 상태: 위험\n"
        analysis += f"**{high_count}개의 높은 심각도 취약점**이 발견되어 즉시 조치가 필요합니다.\n\n"
    elif medium_count > 0:
        analysis += "### 🟡 보안 상태: 주의\n"
        analysis += f"**{medium_count}개의 중간 심각도 취약점**이 발견되어 우선순위를 정해 해결해야 합니다.\n\n"
    
    # 파일 시스템 스캔 분석 - 모든 취약점 포함
    if "error" not in trivy_fs and trivy_fs.get("total_vulnerabilities", 0) > 0:
        analysis += "### 📁 파일 시스템 취약점 분석\n"
        fs_vulns = trivy_fs.get("all_vulnerabilities", [])
        if fs_vulns:
            analysis += f"**발견된 모든 취약점 ({len(fs_vulns)}개)**:\n"
            for i, vuln in enumerate(fs_vulns, 1):
                severity_emoji = "🔴" if vuln['severity'] == 'error' else "🟡" if vuln['severity'] == 'warning' else "🟢"
                analysis += f"{i}. {severity_emoji} **{vuln['severity'].upper()}**: {vuln['message']}\n"
                analysis += f"   - **위치**: {vuln['location']}\n"
                analysis += f"   - **규칙 ID**: {vuln['rule_id']}\n\n"
            
            analysis += "**권장사항**:\n"
            analysis += "- 의존성 패키지를 최신 버전으로 업데이트\n"
            analysis += "- 알려진 취약점이 있는 라이브러리 교체 검토\n"
            analysis += "- 정기적인 보안 업데이트 일정 수립\n"
            analysis += "- 패키지 관리 정책 수립 및 적용\n\n"
    
    # IaC 스캔 분석 - 모든 취약점 포함
    if "error" not in trivy_iac and trivy_iac.get("total_vulnerabilities", 0) > 0:
        analysis += "### 🏗️ 인프라스트럭처 코드 취약점 분석\n"
        iac_vulns = trivy_iac.get("all_vulnerabilities", [])
        if iac_vulns:
            analysis += f"**발견된 모든 취약점 ({len(iac_vulns)}개)**:\n"
            for i, vuln in enumerate(iac_vulns, 1):
                severity_emoji = "🔴" if vuln['severity'] == 'error' else "🟡" if vuln['severity'] == 'warning' else "🟢"
                analysis += f"{i}. {severity_emoji} **{vuln['severity'].upper()}**: {vuln['message']}\n"
                analysis += f"   - **위치**: {vuln['location']}\n"
                analysis += f"   - **규칙 ID**: {vuln['rule_id']}\n\n"
            
            analysis += "**권장사항**:\n"
            analysis += "- Terraform 설정에서 보안 모범 사례 적용\n"
            analysis += "- 민감한 정보가 하드코딩되지 않도록 확인\n"
            analysis += "- 최소 권한 원칙에 따른 리소스 접근 권한 설정\n"
            analysis += "- 인프라 코드 리뷰 프로세스 강화\n\n"
    
    # 일반적인 보안 권장사항
    analysis += "### 🛡️ 일반 보안 권장사항\n"
    if high_count > 0:
        analysis += "1. **즉시 조치**: 높은 심각도 취약점을 우선적으로 해결\n"
    if medium_count > 0:
        analysis += "2. **계획적 조치**: 중간 심각도 취약점에 대한 해결 계획 수립\n"
    analysis += "3. **정기 모니터링**: 자동화된 보안 스캔을 통한 지속적 모니터링\n"
    analysis += "4. **팀 교육**: 보안 모범 사례에 대한 팀원 교육\n"
    analysis += "5. **문서화**: 보안 정책 및 절차 문서화\n"
    analysis += "6. **자동화**: CI/CD 파이프라인에 보안 검사 통합\n"
    
    return analysis

def main():
    """보안 보고서 생성을 위한 메인 함수입니다."""
    print("🔍 Trivy 보안 스캔 결과를 분석하고 AI 보고서를 생성합니다...")
    
    # Trivy 스캔 결과 파싱
    trivy_fs_results = parse_sarif_file("trivy-results.sarif")
    trivy_iac_results = parse_sarif_file("trivy-iac-results.sarif")
    
    # AI 기반 보고서 생성
    report_content = generate_ai_report(trivy_fs_results, trivy_iac_results)
    
    # 보고서 파일에 저장
    output_file = "trivy-security-report.md"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    # 통계 출력
    total_vulns = 0
    if "error" not in trivy_fs_results:
        total_vulns += trivy_fs_results.get("total_vulnerabilities", 0)
    if "error" not in trivy_iac_results:
        total_vulns += trivy_iac_results.get("total_vulnerabilities", 0)
    
    print(f"✅ AI 보안 보고서 생성 완료: {output_file}")
    print(f"📊 발견된 총 취약점: {total_vulns}개")
    
    if total_vulns == 0:
        print("🎉 보안 스캔 결과: 취약점이 발견되지 않았습니다!")
    else:
        print("⚠️  발견된 취약점을 검토하고 조치하시기 바랍니다.")

if __name__ == "__main__":
    main() 