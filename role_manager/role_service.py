# 2. 역할 관리 서비스 모듈 (role_manager/role_service.py)

import json
import time
import datetime
import boto3
import uuid
from common.config import CONFIG
from common.db import get_user_activity_profile, get_role_template, save_role_history

def generate_optimized_role(session, user_arn):
    """
    사용자 행동 패턴에 기반한 최적화된 역할 생성
    
    Args:
        session (boto3.Session): AWS 세션
        user_arn (str): 사용자 ARN
        
    Returns:
        dict: 생성된 역할 정보
    """
    # 사용자 행동 프로파일 조회
    profile = get_user_activity_profile(user_arn)
    if not profile:
        raise ValueError(f"사용자 {user_arn}의 행동 프로파일을 찾을 수 없습니다.")
    
    # 필요한 권한 목록 추출
    required_permissions = profile.get("required_permissions", [])
    
    if not required_permissions:
        raise ValueError(f"사용자 {user_arn}에게 필요한 권한을 추정할 수 없습니다.")
    
    # 역할 템플릿 선택
    template = select_role_template(required_permissions)
    
    # 템플릿 기반 커스텀 정책 생성
    policy_document = create_custom_policy(template, required_permissions)
    
    # IAM에 역할 생성 또는 업데이트
    iam_client = session.client("iam")
    
    # 역할 이름 생성 (사용자 ID 기반)
    user_id = user_arn.split("/")[-1]
    role_name = f"WGA-OptimizedRole-{user_id[:8]}"
    
    try:
        # 기존 역할 확인
        try:
            iam_client.get_role(RoleName=role_name)
            # 역할이 존재하면 정책 업데이트
            role_arn = update_role_policy(iam_client, role_name, policy_document)
            action = "updated"
        except iam_client.exceptions.NoSuchEntityException:
            # 역할이 없으면 새로 생성
            role_arn = create_role(iam_client, role_name, policy_document, user_arn)
            action = "created"
        
        # 역할 변경 이력 저장
        save_role_history({
            "id": str(uuid.uuid4()),
            "role_name": role_name,
            "role_arn": role_arn,
            "user_arn": user_arn,
            "action": action,
            "policy_document": policy_document,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "permissions_count": len(required_permissions)
        })
        
        return {
            "role_name": role_name,
            "role_arn": role_arn,
            "action": action,
            "permissions_count": len(required_permissions),
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
    except Exception as e:
        print(f"Error generating optimized role: {e}")
        raise

def select_role_template(required_permissions):
    """
    필요한 권한에 맞는 최적의 역할 템플릿 선택
    
    Args:
        required_permissions (list): 필요한 권한 목록
        
    Returns:
        dict: 선택된 역할 템플릿
    """
    # 필요한 서비스 그룹 파악
    services = {}
    for permission in required_permissions:
        if ":" in permission:
            service = permission.split(":")[0]
            if service in services:
                services[service] += 1
            else:
                services[service] = 1
    
    # 가장 많이 사용하는 상위 3개 서비스 선택
    top_services = sorted(services.items(), key=lambda x: x[1], reverse=True)[:3]
    top_service_names = [s[0] for s in top_services]
    
    # 템플릿 라이브러리에서 적합한 템플릿 검색
    if "lambda" in top_service_names and "dynamodb" in top_service_names:
        template_id = "serverless-developer"
    elif "ec2" in top_service_names and "s3" in top_service_names:
        template_id = "infrastructure-admin"
    elif "s3" in top_service_names and "dynamodb" in top_service_names:
        template_id = "data-engineer"
    else:
        template_id = "custom"
    
    # 템플릿 조회
    template = get_role_template(template_id)
    
    # 템플릿이 없으면 기본 템플릿 사용
    if not template:
        template = {
            "id": "custom",
            "name": "Custom Template",
            "description": "사용자 지정 역할 템플릿",
            "version": "1.0",
            "policy_structure": {
                "Version": "2012-10-17",
                "Statement": []
            }
        }
    
    return template

def create_custom_policy(template, required_permissions):
    """
    템플릿을 기반으로 커스텀 정책 문서 생성
    
    Args:
        template (dict): 역할 템플릿
        required_permissions (list): 필요한 권한 목록
        
    Returns:
        dict: 정책 문서
    """
    # 템플릿에서 정책 구조 복사
    policy_document = template.get("policy_structure", {
        "Version": "2012-10-17",
        "Statement": []
    })
    
    # 권한을 서비스별로 그룹화
    service_groups = {}
    for permission in required_permissions:
        if ":" in permission:
            service, action = permission.split(":", 1)
            if service in service_groups:
                service_groups[service].append(action)
            else:
                service_groups[service] = [action]
    
    # 서비스별 정책 설명 생성
    statements = []
    for service, actions in service_groups.items():
        statement = {
            "Effect": "Allow",
            "Action": [f"{service}:{action}" for action in actions],
            "Resource": "*"  # 리소스 수준 권한은 더 세밀한 분석 필요
        }
        statements.append(statement)
    
    # 정책 문서에 설명 추가
    policy_document["Statement"] = statements
    
    return policy_document

def create_role(iam_client, role_name, policy_document, user_arn):
    """
    새 IAM 역할 생성
    
    Args:
        iam_client: IAM 클라이언트
        role_name (str): 역할 이름
        policy_document (dict): 정책 문서
        user_arn (str): 사용자 ARN
        
    Returns:
        str: 생성된 역할 ARN
    """
    # 신뢰 관계 설정 (AssumeRole 정책)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": user_arn
                },
                "Action": "sts:AssumeRole",
                "Condition": {}
            }
        ]
    }
    
    # 역할 생성
    response = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description=f"WGA Optimized Role for {user_arn}",
        MaxSessionDuration=3600  # 1시간 세션
    )
    
    role_arn = response["Role"]["Arn"]
    
    # 인라인 정책 추가
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName=f"WGA-OptimizedPolicy-{role_name}",
        PolicyDocument=json.dumps(policy_document)
    )
    
    return role_arn

def update_role_policy(iam_client, role_name, policy_document):
    """
    기존 IAM 역할의 정책 업데이트
    
    Args:
        iam_client: IAM 클라이언트
        role_name (str): 역할 이름
        policy_document (dict): 정책 문서
        
    Returns:
        str: 역할 ARN
    """
    # 역할 정보 조회
    response = iam_client.get_role(RoleName=role_name)
    role_arn = response["Role"]["Arn"]
    
    # 인라인 정책 업데이트
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName=f"WGA-OptimizedPolicy-{role_name}",
        PolicyDocument=json.dumps(policy_document)
    )
    
    return role_arn

def assign_role_to_user(session, user_arn, role_arn):
    """
    사용자에게 최적화된 역할 할당
    
    Args:
        session (boto3.Session): AWS 세션
        user_arn (str): 사용자 ARN
        role_arn (str): 역할 ARN
        
    Returns:
        dict: 할당 결과
    """
    # IAM 클라이언트 초기화
    iam_client = session.client("iam")
    
    # ARN에서 사용자 이름 추출
    user_name = user_arn.split("/")[-1]
    
    try:
        # 기존 사용자 그룹 정보 조회
        current_groups = iam_client.list_groups_for_user(UserName=user_name)
        
        # WGA 관리 그룹 이름 생성
        wga_group_name = f"WGA-RoleGroup-{user_name}"
        
        # 그룹 존재 여부 확인
        try:
            iam_client.get_group(GroupName=wga_group_name)
            # 그룹이 있으면 업데이트
            update_group = True
        except iam_client.exceptions.NoSuchEntityException:
            # 그룹이 없으면 새로 생성
            iam_client.create_group(GroupName=wga_group_name)
            update_group = False
        
        # 그룹에 역할 수임 정책 설정
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": role_arn
                }
            ]
        }
        
        # 그룹에 정책 적용
        iam_client.put_group_policy(
            GroupName=wga_group_name,
            PolicyName=f"AssumeRole-{role_arn.split('/')[-1]}",
            PolicyDocument=json.dumps(assume_role_policy_document)
        )
        
        # 사용자를 그룹에 추가
        if not update_group:
            iam_client.add_user_to_group(
                GroupName=wga_group_name,
                UserName=user_name
            )
        
        return {
            "user_arn": user_arn,
            "role_arn": role_arn,
            "group_name": wga_group_name,
            "action": "updated" if update_group else "created",
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
    except Exception as e:
        print(f"Error assigning role to user: {e}")
        raise