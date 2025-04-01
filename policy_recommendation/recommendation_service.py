# lambda_functions/policy_recommendation/recommendation_service.py
import json
import time
import datetime
import boto3
import uuid
import re
from common.config import CONFIG
from common.db import create_analysis_result, get_user_analysis_results, get_latest_analysis_results
from common.utils import get_aws_session, download_from_s3, get_latest_s3_object

def get_latest_analysis_from_s3(session):
    """
    S3 버킷에서 최신 분석 결과 파일을 가져옵니다.
    
    Args:
        session (boto3.Session): AWS 세션
        
    Returns:
        dict: 분석 결과 데이터
    """
    try:
        # 최신 결과 파일 키 가져오기
        bucket_name = CONFIG['s3']['output_bucket']
        prefix = "results/"
        
        latest_key = get_latest_s3_object(session, bucket_name, prefix)
        
        if not latest_key:
            raise ValueError("결과 파일을 찾을 수 없습니다.")
        
        # 파일 다운로드
        file_data = download_from_s3(session, bucket_name, latest_key)
        
        if not file_data:
            raise ValueError("결과 파일을 다운로드할 수 없습니다.")
        
        # JSON 파싱
        analysis_results = json.loads(file_data)
        
        # 데이터 형식 확인
        if not isinstance(analysis_results, list):
            analysis_results = [analysis_results]
        
        return analysis_results
    except Exception as e:
        print(f"S3에서 분석 결과 가져오기 오류: {e}")
        raise

def store_analysis_results(analysis_results):
    """
    분석 결과를 DynamoDB에 저장합니다.
    
    Args:
        analysis_results (list): 저장할 분석 결과 목록
        
    Returns:
        list: 저장된 결과 ID 목록
    """
    stored_ids = []
    
    for result in analysis_results:
        try:
            # 필수 필드 확인
            if not result.get("user") and not result.get("type") == "daily_global_summary":
                print(f"사용자 정보가 없는 결과 건너뛰기: {result}")
                continue
            
            # DynamoDB에 저장할 데이터 준비
            result_data = {
                "id": str(uuid.uuid4()),
                "date": result.get("date", datetime.datetime.utcnow().strftime('%Y-%m-%d')),
                "user_arn": result.get("user", ""),
                "log_count": result.get("log_count", 0),
                "analysis_timestamp": result.get("analysis_timestamp", ""),
                "analysis_comment": result.get("analysis_comment", ""),
                "risk_level": result.get("risk_level", "Unknown"),
                "policy_recommendation": result.get("policy_recommendation", {
                    "REMOVE": [],
                    "ADD": [],
                    "Reason": ""
                }),
                "created_at": int(time.time())
            }
            
            # 타입 필드가 있으면 추가 (일일 요약 등)
            if "type" in result:
                result_data["type"] = result["type"]
            
            # DynamoDB에 저장
            result_id = create_analysis_result(result_data)
            
            if result_id:
                stored_ids.append(result_id)
        except Exception as e:
            print(f"분석 결과 저장 오류: {e}")
            continue
    
    return stored_ids

def format_policy_recommendations(analysis_results):
    """
    분석 결과를 프론트엔드에 표시하기 좋은 형식으로 포맷합니다.
    
    Args:
        analysis_results (list): 분석 결과 목록
        
    Returns:
        list: 포맷된 분석 결과
    """
    formatted_results = []
    
    for result in analysis_results:
        # 기본 결과 정보
        formatted_result = {
            "date": result.get("date"),
            "user": result.get("user_arn") or result.get("user", ""),
            "log_count": result.get("log_count", 0),
            "analysis_timestamp": result.get("analysis_timestamp", ""),
            "risk_level": result.get("risk_level", "Unknown")
        }
        
        # 분석 코멘트에서 요약 추출
        analysis_comment = result.get("analysis_comment", "")
        summary = extract_summary_from_comment(analysis_comment)
        formatted_result["summary"] = summary or analysis_comment
        
        # 정책 추천 정보 포맷
        policy_recommendation = result.get("policy_recommendation", {})
        
        # 추가해야 할 권한
        add_permissions = []
        for action in policy_recommendation.get("ADD", []):
            add_permissions.append({
                "action": action,
                "apply": False,
                "reason": policy_recommendation.get("Reason", "")
            })
        
        # 제거해야 할 권한
        remove_permissions = []
        for action in policy_recommendation.get("REMOVE", []):
            remove_permissions.append({
                "action": action,
                "apply": False,
                "reason": policy_recommendation.get("Reason", "")
            })
        
        formatted_result["add_permissions"] = add_permissions
        formatted_result["remove_permissions"] = remove_permissions
        
        # 결과에 타입이 있으면 추가 (일일 요약 등)
        if "type" in result:
            formatted_result["type"] = result["type"]
        
        formatted_results.append(formatted_result)
    
    return formatted_results

def extract_summary_from_comment(comment):
    """
    분석 코멘트에서 요약 문장을 추출합니다.
    
    Args:
        comment (str): 분석 코멘트
        
    Returns:
        str: 추출된 요약 또는 None
    """
    if not comment:
        return None
    
    # 요약 마커 패턴
    markers = ["Summary Sentence:", "Summary:", "요약:"]
    
    for marker in markers:
        if marker in comment:
            parts = comment.split(marker)
            if len(parts) > 1:
                # 요약 부분 추출 및 정리
                summary = parts[1].strip()
                # 다음 마커가 있으면 거기까지만 자르기
                for next_marker in markers:
                    if next_marker in summary:
                        summary = summary.split(next_marker)[0].strip()
                return summary
    
    # JSON 형식인 경우 요약 필드 확인
    try:
        if comment.strip().startswith('{') and comment.strip().endswith('}'):
            data = json.loads(comment)
            if data.get('summary'):
                return data['summary']
    except:
        pass
    
    return None

def apply_policy_changes(session, updates):
    """
    사용자의 IAM 정책에 변경 사항을 적용합니다.
    
    Args:
        session (boto3.Session): AWS 세션
        updates (list): 적용할 정책 변경 사항 목록
        
    Returns:
        list: 변경 결과 목록
    """
    iam_client = session.client("iam")
    overall_results = []
    
    for update in updates:
        result = {
            "user": None,
            "added_permissions": [],
            "removed_permissions": [],
            "errors": []
        }
        
        user_arn = update.get("user_arn")
        if not user_arn:
            overall_results.append({
                "status": "error",
                "message": "사용자 ARN이 누락되었습니다.",
                "details": result
            })
            continue
        
        # ARN에서 사용자 이름 추출
        if ":user/" in user_arn:
            user_name = user_arn.split("/")[-1]
            result["user"] = user_name
        elif ":assumed-role/" in user_arn:
            overall_results.append({
                "status": "error",
                "message": "역할(Role) 권한은 현재 수정할 수 없습니다. IAM 사용자(User)만 지원됩니다.",
                "details": {"user": user_arn}
            })
            continue
        else:
            overall_results.append({
                "status": "error",
                "message": f"지원되지 않는 ARN 형식입니다: {user_arn}",
                "details": {"user": user_arn}
            })
            continue
        
        # 적용할 권한 변경 사항 추출
        add_permissions = [item.get("action") for item in update.get("add_permissions", []) 
                          if item.get("apply") and item.get("action")]
        
        remove_permissions = [item.get("action") for item in update.get("remove_permissions", []) 
                             if item.get("apply") and item.get("action")]
        
        if not add_permissions and not remove_permissions:
            overall_results.append({
                "status": "info",
                "message": "적용할 변경 사항이 없습니다.",
                "details": result
            })
            continue
        
        # 정책 변경 적용
        try:
            # 현재 사용자 정책 조회
            policy_names = iam_client.list_user_policies(UserName=user_name).get("PolicyNames", [])
            wga_policy_name = "WGALogAnalysisInlinePolicy"
            
            if wga_policy_name in policy_names:
                # 기존 정책 가져오기
                policy_response = iam_client.get_user_policy(
                    UserName=user_name,
                    PolicyName=wga_policy_name
                )
                policy_document = policy_response.get("PolicyDocument", {})
            else:
                # 새 정책 생성
                policy_document = {
                    "Version": "2012-10-17",
                    "Statement": []
                }
            
            # 권한 추가
            if add_permissions:
                # Allow 효과를 가진 Statement 찾기 또는 생성
                allow_stmt = None
                for stmt in policy_document.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        allow_stmt = stmt
                        break
                
                if not allow_stmt:
                    allow_stmt = {
                        "Effect": "Allow",
                        "Action": [],
                        "Resource": "*"
                    }
                    policy_document["Statement"].append(allow_stmt)
                
                # Action 필드 확인 및 초기화
                if "Action" not in allow_stmt:
                    allow_stmt["Action"] = []
                
                # 문자열인 경우 리스트로 변환
                if isinstance(allow_stmt["Action"], str):
                    allow_stmt["Action"] = [allow_stmt["Action"]]
                
                # 권한 추가
                for permission in add_permissions:
                    if permission not in allow_stmt["Action"]:
                        allow_stmt["Action"].append(permission)
                        result["added_permissions"].append(permission)
            
            # 권한 제거
            if remove_permissions:
                for stmt in policy_document.get("Statement", []):
                    if stmt.get("Effect") == "Allow" and "Action" in stmt:
                        if isinstance(stmt["Action"], str):
                            if stmt["Action"] in remove_permissions:
                                result["removed_permissions"].append(stmt["Action"])
                                # 문자열 형태일 경우 빈 문자열로 설정
                                stmt["Action"] = ""
                        elif isinstance(stmt["Action"], list):
                            for permission in remove_permissions:
                                if permission in stmt["Action"]:
                                    stmt["Action"].remove(permission)
                                    result["removed_permissions"].append(permission)
            
            # 빈 Action 필드를 가진 Statement 제거
            policy_document["Statement"] = [
                stmt for stmt in policy_document.get("Statement", [])
                if (
                    (isinstance(stmt.get("Action"), list) and len(stmt.get("Action")) > 0)
                    or (isinstance(stmt.get("Action"), str) and stmt.get("Action").strip() != "")
                )
            ]
            
            # 정책 적용
            if not policy_document["Statement"]:
                # 모든 statement가 제거되었으므로, 인라인 정책을 삭제
                iam_client.delete_user_policy(
                    UserName=user_name,
                    PolicyName=wga_policy_name
                )
            else:
                iam_client.put_user_policy(
                    UserName=user_name,
                    PolicyName=wga_policy_name,
                    PolicyDocument=json.dumps(policy_document)
                )
            
            overall_results.append({
                "status": "success",
                "message": "IAM 정책이 성공적으로 업데이트되었습니다.",
                "details": result
            })
            
        except Exception as e:
            result["errors"].append(str(e))
            overall_results.append({
                "status": "error",
                "message": f"IAM 정책 업데이트 중 오류가 발생했습니다: {str(e)}",
                "details": result
            })
    
    return overall_results

def get_iam_user_permissions(session, user_name):
    """
    IAM 사용자의 현재 권한을 조회합니다.
    
    Args:
        session (boto3.Session): AWS 세션
        user_name (str): IAM 사용자 이름
        
    Returns:
        dict: 사용자 권한 정보
    """
    iam_client = session.client("iam")
    
    try:
        # 인라인 정책 조회
        inline_policies = []
        policy_names = iam_client.list_user_policies(UserName=user_name).get("PolicyNames", [])
        
        for policy_name in policy_names:
            policy_response = iam_client.get_user_policy(
                UserName=user_name,
                PolicyName=policy_name
            )
            policy_document = policy_response.get("PolicyDocument", {})
            
            inline_policies.append({
                "name": policy_name,
                "document": policy_document
            })
        
        # 관리형 정책 조회
        managed_policies = []
        attached_policies = iam_client.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
        
        for policy in attached_policies:
            policy_arn = policy.get("PolicyArn")
            policy_version = iam_client.get_policy(PolicyArn=policy_arn).get("Policy", {}).get("DefaultVersionId")
            
            policy_document = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy_version
            ).get("PolicyVersion", {}).get("Document", {})
            
            managed_policies.append({
                "name": policy.get("PolicyName"),
                "arn": policy_arn,
                "document": policy_document
            })
        
        # 사용자 그룹 조회
        groups = []
        user_groups = iam_client.list_groups_for_user(UserName=user_name).get("Groups", [])
        
        for group in user_groups:
            group_name = group.get("GroupName")
            
            # 그룹 인라인 정책 조회
            group_policies = []
            group_policy_names = iam_client.list_group_policies(GroupName=group_name).get("PolicyNames", [])
            
            for policy_name in group_policy_names:
                policy_response = iam_client.get_group_policy(
                    GroupName=group_name,
                    PolicyName=policy_name
                )
                policy_document = policy_response.get("PolicyDocument", {})
                
                group_policies.append({
                    "name": policy_name,
                    "document": policy_document
                })
            
            # 그룹 관리형 정책 조회
            group_managed_policies = []
            group_attached_policies = iam_client.list_attached_group_policies(GroupName=group_name).get("AttachedPolicies", [])
            
            for policy in group_attached_policies:
                policy_arn = policy.get("PolicyArn")
                policy_version = iam_client.get_policy(PolicyArn=policy_arn).get("Policy", {}).get("DefaultVersionId")
                
                policy_document = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_version
                ).get("PolicyVersion", {}).get("Document", {})
                
                group_managed_policies.append({
                    "name": policy.get("PolicyName"),
                    "arn": policy_arn,
                    "document": policy_document
                })
            
            groups.append({
                "name": group_name,
                "inline_policies": group_policies,
                "managed_policies": group_managed_policies
            })
        
        return {
            "user_name": user_name,
            "inline_policies": inline_policies,
            "managed_policies": managed_policies,
            "groups": groups
        }
    except Exception as e:
        print(f"Error getting user permissions: {e}")
        raise

def get_policy_summary(permissions_data):
    """
    사용자 권한 정보에서 간략한 요약을 생성합니다.
    
    Args:
        permissions_data (dict): get_iam_user_permissions()의 결과
        
    Returns:
        dict: 권한 요약 정보
    """
    # 모든 권한 액션 수집
    actions = []
    
    # 인라인 정책에서 권한 수집
    for policy in permissions_data.get("inline_policies", []):
        for stmt in policy.get("document", {}).get("Statement", []):
            if stmt.get("Effect") == "Allow":
                action = stmt.get("Action")
                if isinstance(action, str):
                    actions.append(action)
                elif isinstance(action, list):
                    actions.extend(action)
    
    # 관리형 정책에서 권한 수집
    for policy in permissions_data.get("managed_policies", []):
        for stmt in policy.get("document", {}).get("Statement", []):
            if stmt.get("Effect") == "Allow":
                action = stmt.get("Action")
                if isinstance(action, str):
                    actions.append(action)
                elif isinstance(action, list):
                    actions.extend(action)
    
    # 그룹 권한 수집
    for group in permissions_data.get("groups", []):
        # 그룹 인라인 정책
        for policy in group.get("inline_policies", []):
            for stmt in policy.get("document", {}).get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    action = stmt.get("Action")
                    if isinstance(action, str):
                        actions.append(action)
                    elif isinstance(action, list):
                        actions.extend(action)
        
        # 그룹 관리형 정책
        for policy in group.get("managed_policies", []):
            for stmt in policy.get("document", {}).get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    action = stmt.get("Action")
                    if isinstance(action, str):
                        actions.append(action)
                    elif isinstance(action, list):
                        actions.extend(action)
    
    # 권한 분류 (서비스별)
    service_permissions = {}
    
    for action in actions:
        if ":" in action:
            service = action.split(":")[0]
            if service in service_permissions:
                service_permissions[service].append(action)
            else:
                service_permissions[service] = [action]
    
    # 결과 구성
    return {
        "user_name": permissions_data.get("user_name"),
        "total_permissions": len(actions),
        "unique_permissions": len(set(actions)),
        "services_count": len(service_permissions),
        "services": [
            {
                "service": service,
                "actions_count": len(actions_list),
                "actions": sorted(actions_list)
            }
            for service, actions_list in sorted(service_permissions.items())
        ]
    }