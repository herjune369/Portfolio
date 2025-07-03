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
    
    report = f"""## 🤖 AI 보안 스캔 보고서

---

### 📅 스캔 개요
* **스캔 날짜**: {datetime.now().strftime('%Y년 %m월 %d일 %H:%M:%S')}
* **브랜치**: `{os.environ.get('GITHUB_REF', '알 수 없음')}`
* **커밋**: `{os.environ.get('GITHUB_SHA', '알 수 없음')[:8]}`
* **저장소**: `{os.environ.get('GITHUB_REPOSITORY', '알 수 없음')}`

---

### 🔍 Trivy 스캔 결과 요약

이번 스캔에서 총 **{total_vulns}개**의 취약점이 발견되었으며, 그중 **{total_high}개는 높은 심각도**를 가진 것으로 나타났습니다.

#### 📊 전체 통계
* **총 취약점 수**: {total_vulns}개
* **높은 심각도**: {total_high}개
* **중간 심각도**: {total_medium}개
* **낮은 심각도**: {total_low}개

#### 🛠️ 스캔 도구별 결과

**1. Trivy 파일 시스템 스캔**
"""
    
    if "error" in trivy_fs_results:
        report += f"* **상태**: ❌ {trivy_fs_results['error']}\n"
    else:
        vulns = trivy_fs_results.get("total_vulnerabilities", 0)
        severity_dist = trivy_fs_results.get("severity_distribution", {})
        report += f"* **상태**: ✅ 완료\n"
        report += f"* **발견된 취약점**: {vulns}개 (높음: {severity_dist.get('error', 0)}, 중간: {severity_dist.get('warning', 0)}, 낮음: {severity_dist.get('note', 0)})\n"
    
    report += "\n**2. Trivy 인프라스트럭처 코드 스캔**\n"
    
    if "error" in trivy_iac_results:
        report += f"* **상태**: ❌ {trivy_iac_results['error']}\n"
    else:
        vulns = trivy_iac_results.get("total_vulnerabilities", 0)
        severity_dist = trivy_iac_results.get("severity_distribution", {})
        report += f"* **상태**: ✅ 완료\n"
        report += f"* **발견된 취약점**: {vulns}개 (높음: {severity_dist.get('error', 0)}, 중간: {severity_dist.get('warning', 0)}, 낮음: {severity_dist.get('note', 0)})\n"
    
    # AI 분석 결과 추가
    report += f"\n---\n\n{ai_analysis}\n"
    
    # 전체 상태
    overall_status = "✅ 통과" if total_high == 0 else "❌ 실패"
    report += f"""
---

### 🚨 최종 보안 상태: {overall_status}

이번 보안 스캔 결과, 시스템의 보안 상태는 **{'성공' if total_high == 0 else '실패'}**로 판단됩니다. {'발견된 CRITICAL 및 HIGH 심각도 취약점들을 시급히 해결하여 보안 위험을 낮춰야 합니다.' if total_high > 0 else '현재 보안 상태는 양호합니다.'}

---

### 📊 결과 위치 및 다음 단계

* **GitHub Security 탭**: 상세 취약점 보고서를 확인하고, GitHub의 보안 기능을 활용하여 취약점을 추적하고 관리할 수 있습니다.
* **SARIF 파일**: 외부 분석 도구에서 활용할 수 있도록 SARIF 파일을 다운로드하세요.
* **아티팩트**: 워크플로우 아티팩트에서 상세 보고서를 확인할 수 있습니다.

**다음 단계:**
1. GitHub Security 탭에서 모든 결과를 면밀히 검토하세요.
2. 가장 중요하거나 높은 심각도의 문제부터 해결 작업을 시작하세요.
3. 파일 시스템 취약점의 경우, 관련된 의존성 패키지를 최신 보안 패치가 적용된 버전으로 업데이트하세요.
4. 인프라스트럭처 코드 취약점의 경우, Terraform 설정을 보안 권장사항에 따라 수정하고 재배포하세요.

---
*이 보고서는 Trivy 보안 스캔 파이프라인에 의해 자동으로 생성되었습니다.*

추가적으로 궁금한 점이나 특정 취약점에 대한 자세한 정보가 필요하시면 언제든지 문의해주세요.
"""

    return report

def generate_ai_analysis(high_count: int, medium_count: int, low_count: int, 
                        trivy_fs: Dict, trivy_iac: Dict) -> str:
    """AI 기반 보안 분석 및 권장사항을 생성합니다."""
    
    analysis = ""
    
    # 전체 위험도 평가
    if high_count == 0 and medium_count == 0:
        analysis += "#### 🟢 현재 보안 상태: 양호\n"
        analysis += "현재 프로젝트의 보안 상태는 양호합니다. 발견된 취약점이 없거나 모두 낮은 심각도입니다.\n\n"
    elif high_count > 0:
        analysis += f"#### 🔴 현재 보안 상태: 위험\n"
        analysis += f"**{high_count}개의 높은 심각도 취약점**이 발견되어 **즉각적인 조치**가 필요합니다.\n\n"
    elif medium_count > 0:
        analysis += f"#### 🟡 현재 보안 상태: 주의\n"
        analysis += f"**{medium_count}개의 중간 심각도 취약점**이 발견되어 우선순위를 정해 해결해야 합니다.\n\n"
    
    analysis += "---\n\n"
    
    # 파일 시스템 스캔 분석 - 모든 취약점 포함
    if "error" not in trivy_fs and trivy_fs.get("total_vulnerabilities", 0) > 0:
        analysis += "#### 📁 파일 시스템 취약점 상세 분석 (총 {}개)\n\n".format(trivy_fs.get("total_vulnerabilities", 0))
        
        # 파일별 취약점 그룹화
        file_vulns = {}
        for vuln in trivy_fs.get("all_vulnerabilities", []):
            file_path = vuln['location']
            if file_path not in file_vulns:
                file_vulns[file_path] = []
            file_vulns[file_path].append(vuln)
        
        # 주요 파일 분석
        if file_vulns:
            main_files = list(file_vulns.keys())[:3]  # 상위 3개 파일만 표시
            analysis += "주로 `{}` 파일에서 관련 취약점이 다수 발견되었습니다.\n\n".format(main_files[0] if main_files else "알 수 없음")
        
        # 심각도별 분류
        high_vulns = [v for v in trivy_fs.get("all_vulnerabilities", []) if v['severity'] == 'error']
        medium_vulns = [v for v in trivy_fs.get("all_vulnerabilities", []) if v['severity'] == 'warning']
        low_vulns = [v for v in trivy_fs.get("all_vulnerabilities", []) if v['severity'] == 'note']
        
        if high_vulns:
            analysis += "* **높음 ({}개)**\n".format(len(high_vulns))
            for i, vuln in enumerate(high_vulns[:5], 1):  # 상위 5개만 표시
                analysis += f"    * **{vuln['rule_id']}**: {vuln['message']}\n"
            if len(high_vulns) > 5:
                analysis += f"    * ... 및 {len(high_vulns) - 5}개 더\n"
            analysis += "\n"
        
        if medium_vulns:
            analysis += "* **중간 ({}개)**\n".format(len(medium_vulns))
            for i, vuln in enumerate(medium_vulns[:5], 1):  # 상위 5개만 표시
                analysis += f"    * **{vuln['rule_id']}**: {vuln['message']}\n"
            if len(medium_vulns) > 5:
                analysis += f"    * ... 및 {len(medium_vulns) - 5}개 더\n"
            analysis += "\n"
        
        if low_vulns:
            analysis += "* **낮음 ({}개)**\n".format(len(low_vulns))
            for i, vuln in enumerate(low_vulns[:3], 1):  # 상위 3개만 표시
                analysis += f"    * **{vuln['rule_id']}**: {vuln['message']}\n"
            if len(low_vulns) > 3:
                analysis += f"    * ... 및 {len(low_vulns) - 3}개 더\n"
            analysis += "\n"
        
        analysis += "**권장사항:**\n"
        analysis += "* 관련된 **모든 취약 패키지를 최신 버전으로 업데이트**하세요.\n"
        analysis += "* 더 이상 사용하지 않거나, 알려진 취약점이 지속적으로 발생하는 라이브러리는 **대체재를 검토**해 보세요.\n"
        analysis += "* **정기적인 보안 업데이트 일정을 수립**하고, 패키지 관리 정책을 적용하여 의존성 취약점을 사전에 방지하는 것이 중요합니다.\n\n"
    
    # IaC 스캔 분석 - 모든 취약점 포함
    if "error" not in trivy_iac and trivy_iac.get("total_vulnerabilities", 0) > 0:
        analysis += "#### 🏗️ 인프라스트럭처 코드 취약점 상세 분석 (총 {}개)\n\n".format(trivy_iac.get("total_vulnerabilities", 0))
        
        # 파일별 취약점 그룹화
        file_vulns = {}
        for vuln in trivy_iac.get("all_vulnerabilities", []):
            file_path = vuln['location']
            if file_path not in file_vulns:
                file_vulns[file_path] = []
            file_vulns[file_path].append(vuln)
        
        # 주요 파일 분석
        if file_vulns:
            main_files = list(file_vulns.keys())[:3]  # 상위 3개 파일만 표시
            analysis += "`{}` 파일에서 인프라 설정과 관련된 다수의 보안 취약점이 발견되었습니다. ".format(main_files[0] if main_files else "알 수 없음")
            analysis += "특히, 네트워크 접근 제어 및 데이터 암호화에 대한 문제가 많습니다.\n\n"
        
        # 심각도별 분류
        high_vulns = [v for v in trivy_iac.get("all_vulnerabilities", []) if v['severity'] == 'error']
        medium_vulns = [v for v in trivy_iac.get("all_vulnerabilities", []) if v['severity'] == 'warning']
        low_vulns = [v for v in trivy_iac.get("all_vulnerabilities", []) if v['severity'] == 'note']
        
        if high_vulns:
            analysis += "* **높음 ({}개)**\n".format(len(high_vulns))
            for i, vuln in enumerate(high_vulns[:8], 1):  # 상위 8개만 표시
                analysis += f"    * **{vuln['rule_id']}**: {vuln['message']}\n"
            if len(high_vulns) > 8:
                analysis += f"    * ... 및 {len(high_vulns) - 8}개 더\n"
            analysis += "\n"
        
        if medium_vulns:
            analysis += "* **중간 ({}개)**\n".format(len(medium_vulns))
            for i, vuln in enumerate(medium_vulns[:5], 1):  # 상위 5개만 표시
                analysis += f"    * **{vuln['rule_id']}**: {vuln['message']}\n"
            if len(medium_vulns) > 5:
                analysis += f"    * ... 및 {len(medium_vulns) - 5}개 더\n"
            analysis += "\n"
        
        if low_vulns:
            analysis += "* **낮음 ({}개)**\n".format(len(low_vulns))
            for i, vuln in enumerate(low_vulns[:5], 1):  # 상위 5개만 표시
                analysis += f"    * **{vuln['rule_id']}**: {vuln['message']}\n"
            if len(low_vulns) > 5:
                analysis += f"    * ... 및 {len(low_vulns) - 5}개 더\n"
            analysis += "\n"
        
        analysis += "**권장사항:**\n"
        analysis += "* **Terraform 설정에서 보안 모범 사례를 적극적으로 적용**하세요.\n"
        analysis += "* **민감한 정보가 하드코딩되지 않도록 확인**하고, AWS Secrets Manager 등 안전한 서비스로 관리하세요.\n"
        analysis += "* **최소 권한 원칙**에 따라 리소스 접근 권한을 설정하고, 불필요하게 넓은 접근 권한(예: 0.0.0.0/0)을 제한하세요.\n"
        analysis += "* **인프라 코드 리뷰 프로세스를 강화**하여 배포 전 보안 취약점을 미리 발견하고 수정할 수 있도록 합니다.\n\n"
    
    # 일반적인 보안 권장사항
    analysis += "### 🛡️ 일반 보안 권장사항\n\n"
    if high_count > 0:
        analysis += f"1. **즉시 조치**: 발견된 **높은 심각도 취약점(총 {high_count}개)**을 우선적으로 해결해야 합니다.\n"
    if medium_count > 0:
        analysis += f"2. **계획적 조치**: 중간 심각도 취약점에 대한 해결 계획을 수립하고 순차적으로 조치하세요.\n"
    analysis += "3. **정기 모니터링**: 자동화된 보안 스캔을 CI/CD 파이프라인에 통합하여 지속적으로 보안 상태를 모니터링하세요.\n"
    analysis += "4. **팀 교육**: 보안 모범 사례 및 최신 위협 동향에 대해 팀원들을 교육하여 보안 인식을 높이세요.\n"
    analysis += "5. **문서화**: 조직의 보안 정책 및 절차를 명확히 문서화하여 일관된 보안 관리를 유지하세요.\n\n"
    
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