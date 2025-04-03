# 3. 제로 트러스트 정책 적용 모듈 (zero_trust_enforcer/enforcer_service.py)

import json
import boto3
import time
import datetime
import uuid
import ipaddress
from common.config import CONFIG
from common.db import get_user_activity_profile, save_access_decision

def evaluate_access_request(session, user_arn, action, resource, context):
    """
    제로 트러스트 원칙에 기반한 접근 요청 평가
    
    Args:
        session (boto3.Session): AWS 세션
        user_arn (str): 사용자 ARN
        action (str): 요청된 액션 (API 호출)
        resource (str): 접근 대상 리소스
        context (dict): 접근 컨텍스트 정보
        
    Returns:
        dict: 접근 평가 결과
    """
    # 컨텍스트 검증
    context_score = validate_context(user_arn, context)
    
    # 사용자 행동 프로파일과 요청 비교
    behavior_score = compare_with_behavior_profile(user_arn, action, resource, context)
    
    # 리소스 민감도 평가
    resource_score = evaluate_resource_sensitivity(resource, action)
    
    # 위험 점수 계산
    risk_score = calculate_risk_score(context_score, behavior_score, resource_score)
    
    # 위험 수준에 따른 접근 결정
    if risk_score < 30:
        decision = "allow"
        expiration = 3600  # 1시간
    elif risk_score < 70:
        # 중간 위험: 추가 인증 필요 & 짧은 세션
        decision = "require_mfa"
        expiration = 1800  # 30분
    else:
        # 높은 위험: 접근 거부
        decision = "deny"
        expiration = 0
    
    # 결과 구성
    result = {
        "request_id": str(uuid.uuid4()),
        "user_arn": user_arn,
        "action": action,
        "resource": resource,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "context": context,
        "risk_score": risk_score,
        "decision": decision,
        "expires_at": int(time.time() + expiration) if expiration > 0 else None,
        "factors": {
            "context_score": context_score,
            "behavior_score": behavior_score,
            "resource_score": resource_score
        }
    }
    
    # 결정 저장
    save_access_decision(result)
    
    return result

def validate_context(user_arn, context):
    """
    접근 컨텍스트 정보 검증
    
    Args:
        user_arn (str): 사용자 ARN
        context (dict): 접근 컨텍스트 정보
        
    Returns:
        dict: 컨텍스트 점수 및 세부 정보
    """
    # 초기 점수 (낮을수록 안전)
    score = 0
    factors = []
    
    # 1. 소스 IP 검증
    source_ip = context.get("source_ip")
    if source_ip:
        ip_factor = validate_source_ip(user_arn, source_ip)
        score += ip_factor["score"]
        factors.append(ip_factor)
    else:
        # IP 정보 없음 (의심스러움)
        score += 30
        factors.append({
            "type": "missing_source_ip",
            "score": 30,
            "message": "소스 IP 정보가 제공되지 않았습니다."
        })
    
    # 2. 디바이스 정보 검증
    device_id = context.get("device_id")
    if device_id:
        device_factor = validate_device(user_arn, device_id, context.get("user_agent"))
        score += device_factor["score"]
        factors.append(device_factor)
    else:
        # 디바이스 정보 없음
        score += 20
        factors.append({
            "type": "missing_device_info",
            "score": 20,
            "message": "디바이스 정보가 제공되지 않았습니다."
        })
    
    # 3. 접속 시간 검증
    time_factor = validate_access_time(user_arn, context.get("timestamp"))
    score += time_factor["score"]
    factors.append(time_factor)
    
    # 4. 위치 정보 검증 (있는 경우)
    geolocation = context.get("geolocation")
    if geolocation:
        location_factor = validate_location(user_arn, geolocation)
        score += location_factor["score"]
        factors.append(location_factor)
    
    # 5. MFA 사용 여부
    mfa_used = context.get("mfa_used", False)
    mfa_score = 0 if mfa_used else 25
    factors.append({
        "type": "mfa_status",
        "score": mfa_score,
        "mfa_used": mfa_used,
        "message": "MFA가 사용됨" if mfa_used else "MFA가 사용되지 않음"
    })
    score += mfa_score
    
    return {
        "score": min(100, score),  # 최대 100점
        "factors": factors
    }

def validate_source_ip(user_arn, source_ip):
    """
    소스 IP 주소 검증
    """
    # 사용자 프로파일에서 일반적인 IP 목록 가져오기
    profile = get_user_activity_profile(user_arn)
    known_ips = profile.get("ip_addresses", []) if profile else []
    
    # 내부 네트워크 IP 확인
    try:
        ip = ipaddress.ip_address(source_ip)
        is_private = ip.is_private
    except ValueError:
        is_private = False
    
    # 알려진 IP인지 확인
    is_known_ip = source_ip in known_ips
    
    # 점수 계산
    if is_known_ip and is_private:
        # 알려진 내부 IP
        score = 0
        message = "알려진 내부 IP 주소입니다."
    elif is_known_ip:
        # 알려진 외부 IP
        score = 10
        message = "알려진 외부 IP 주소입니다."
    elif is_private:
        # 새로운 내부 IP
        score = 20
        message = "새로운 내부 IP 주소입니다."
    else:
        # 새로운 외부 IP
        score = 40
        message = "새로운 외부 IP 주소입니다."
    
    return {
        "type": "source_ip",
        "score": score,
        "ip": source_ip,
        "is_known": is_known_ip,
        "is_private": is_private,
        "message": message
    }
def validate_access_time(user_arn, timestamp):
    """
    접속 시간 검증
    """
    # 현재 시간 가져오기 (timestamp가 없는 경우)
    current_time = datetime.datetime.now(datetime.timezone.utc)
    if timestamp:
        try:
            # ISO 형식 타임스탬프 파싱
            access_time = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            access_time = current_time
    else:
        access_time = current_time
    
    # 사용자 프로파일에서 일반적인 활동 시간 패턴 가져오기
    profile = get_user_activity_profile(user_arn)
    
    if not profile or "normal_patterns" not in profile:
        # 프로파일이 없는 경우 기본값 (업무 시간) 사용
        active_hours = list(range(9, 18))  # 9AM-6PM
        primary_days = [0, 1, 2, 3, 4]     # 월-금
    else:
        patterns = profile.get("normal_patterns", {})
        active_hours = patterns.get("active_hours", list(range(9, 18)))
        primary_days = patterns.get("primary_days", [0, 1, 2, 3, 4])
    
    # 현재 시간이 활동 패턴에 맞는지 확인
    current_hour = access_time.hour
    current_day = access_time.weekday()
    
    hour_match = current_hour in active_hours
    day_match = current_day in primary_days
    
    # 업무 시간 중인지 확인 (9AM-6PM, 월-금)
    is_business_hours = 9 <= current_hour < 18 and current_day < 5
    
    # 점수 계산
    if hour_match and day_match:
        # 정상 활동 시간 및 요일
        score = 0
        message = "정상 활동 시간 및 요일입니다."
    elif day_match:
        # 정상 요일이지만 비정상 시간
        score = 20
        message = "일반적인 요일이지만 비정상적인 시간입니다."
    elif hour_match:
        # 정상 시간이지만 비정상 요일
        score = 15
        message = "일반적인 시간이지만 비정상적인 요일입니다."
    elif is_business_hours:
        # 표준 업무 시간이지만 사용자의 정상 패턴은 아님
        score = 10
        message = "표준 업무 시간입니다."
    else:
        # 완전히 비정상적인 시간 및 요일
        score = 35
        message = "비정상적인 접속 시간 및 요일입니다."
    
    return {
        "type": "access_time",
        "score": score,
        "time": access_time.isoformat(),
        "hour": current_hour,
        "day": current_day,
        "matches_pattern": hour_match and day_match,
        "is_business_hours": is_business_hours,
        "message": message
    }

def validate_location(user_arn, geolocation):
    """
    위치 정보 검증
    """
    # 사용자 프로파일에서 일반적인 위치 정보 가져오기
    profile = get_user_activity_profile(user_arn)
    known_locations = profile.get("locations", []) if profile else []
    
    # 새 위치 정보 파싱
    country = geolocation.get("country")
    city = geolocation.get("city")
    
    # 알려진 위치인지 확인
    is_known_location = False
    for loc in known_locations:
        if loc.get("country") == country and loc.get("city") == city:
            is_known_location = True
            break
    
    # 점수 계산
    if is_known_location:
        # 알려진 위치
        score = 0
        message = "알려진 위치입니다."
    elif country and any(loc.get("country") == country for loc in known_locations):
        # 알려진 국가이지만 새로운 도시
        score = 20
        message = "알려진 국가의 새로운 도시입니다."
    elif country:
        # 완전히 새로운 국가
        score = 40
        message = "새로운 국가에서의 접속입니다."
    else:
        # 위치 정보 불완전
        score = 30
        message = "불완전한 위치 정보입니다."
    
    return {
        "type": "location",
        "score": score,
        "country": country,
        "city": city,
        "is_known": is_known_location,
        "message": message
    }

def parse_user_agent(user_agent_string):
    """
    User-Agent 문자열 파싱하여 디바이스 정보 추출
    """
    if not user_agent_string:
        return {}
    
    device_info = {
        "original": user_agent_string
    }
    
    # 간단한 파싱 (실제 구현시에는 더 정교한 라이브러리 사용 권장)
    if "Windows" in user_agent_string:
        device_info["os"] = "Windows"
    elif "Mac OS X" in user_agent_string:
        device_info["os"] = "macOS"
    elif "Linux" in user_agent_string:
        device_info["os"] = "Linux"
    elif "iOS" in user_agent_string:
        device_info["os"] = "iOS"
    elif "Android" in user_agent_string:
        device_info["os"] = "Android"
    else:
        device_info["os"] = "Unknown"
    
    # 브라우저 정보 추출
    if "Chrome" in user_agent_string and "Edg" not in user_agent_string:
        device_info["browser"] = "Chrome"
    elif "Firefox" in user_agent_string:
        device_info["browser"] = "Firefox"
    elif "Safari" in user_agent_string and "Chrome" not in user_agent_string:
        device_info["browser"] = "Safari"
    elif "Edg" in user_agent_string:
        device_info["browser"] = "Edge"
    elif "MSIE" in user_agent_string or "Trident" in user_agent_string:
        device_info["browser"] = "Internet Explorer"
    else:
        device_info["browser"] = "Unknown"
    
    # 모바일 여부 확인
    device_info["is_mobile"] = "Mobile" in user_agent_string or "Android" in user_agent_string
    
    return device_info

def compare_with_behavior_profile(user_arn, action, resource, context):
    """
    사용자 행동 프로파일과 요청 비교
    
    Args:
        user_arn (str): 사용자 ARN
        action (str): 요청된 액션
        resource (str): 접근 대상 리소스
        context (dict): 접근 컨텍스트 정보
        
    Returns:
        dict: 행동 점수 및 세부 정보
    """
    # 사용자 행동 프로파일 조회
    profile = get_user_activity_profile(user_arn)
    
    if not profile:
        # 프로파일이 없는 경우
        return {
            "score": 50,  # 중간 위험도로 설정
            "message": "사용자 행동 프로파일이 없습니다.",
            "factors": []
        }
    
    # 점수 초기화
    score = 0
    factors = []
    
    # 1. 액션 패턴 분석
    action_factor = analyze_action_pattern(action, profile)
    score += action_factor["score"]
    factors.append(action_factor)
    
    # 2. 리소스 접근 패턴 분석
    resource_factor = analyze_resource_pattern(resource, profile)
    score += resource_factor["score"]
    factors.append(resource_factor)
    
    # 3. 행동 시퀀스 분석 (최근 액션들과의 연관성)
    sequence_factor = analyze_action_sequence(action, context.get("recent_actions", []), profile)
    score += sequence_factor["score"]
    factors.append(sequence_factor)
    
    return {
        "score": min(100, score),  # 최대 100점
        "factors": factors
    }

def analyze_action_pattern(action, profile):
    """
    액션이 사용자의 일반적인 사용 패턴에 맞는지 분석
    """
    # 프로파일에서 자주 사용하는 API 목록 가져오기
    frequent_apis = profile.get("frequent_apis", [])
    service_usage = profile.get("service_usage", {})
    api_counts = service_usage.get("api_counts", {})
    
    # 액션 파싱 (예: "s3:GetObject" -> "GetObject")
    if ":" in action:
        service, api = action.split(":", 1)
    else:
        service, api = "unknown", action
    
    # 자주 사용하는 API인지 확인
    is_frequent_api = api in frequent_apis
    
    # API 사용 빈도 확인
    api_frequency = api_counts.get(api, 0)
    
    # 점수 계산
    if is_frequent_api:
        # 자주 사용하는 API
        score = 0
        message = "자주 사용하는 API입니다."
    elif api_frequency > 0:
        # 가끔 사용하는 API
        score = 15
        message = "가끔 사용하는 API입니다."
    else:
        # 처음 사용하는 API
        score = 35
        message = "처음 사용하는 API입니다."
    
    # 특히 위험한 API인 경우 추가 점수
    sensitive_apis = [
        "DeleteUser", "CreateUser", "CreateAccessKey", "PutRolePolicy",
        "DeleteDBInstance", "StopInstances", "TerminateInstances"
    ]
    
    if api in sensitive_apis:
        score += 25
        message += " (민감한 작업)"
    
    return {
        "type": "action_pattern",
        "score": score,
        "action": action,
        "is_frequent": is_frequent_api,
        "frequency": api_frequency,
        "message": message
    }

def analyze_resource_pattern(resource, profile):
    """
    리소스 접근이 사용자의 일반적인 패턴에 맞는지 분석
    """
    # 프로파일에서 자주 접근하는 리소스 목록 가져오기
    resource_access = profile.get("resource_access", {})
    resource_name_counts = resource_access.get("resource_name_counts", {})
    resource_type_counts = resource_access.get("resource_type_counts", {})
    
    # 리소스 타입 및 이름 추출
    resource_type = "unknown"
    resource_name = resource
    
    # ARN 형식 리소스인 경우 파싱
    if resource.startswith("arn:aws:"):
        parts = resource.split(":")
        if len(parts) >= 6:
            resource_type = parts[2]  # 서비스 (예: s3, ec2)
            resource_name = parts[5]  # 리소스 이름
    
    # 자주 접근하는 리소스인지 확인
    is_frequent_resource = resource_name in resource_name_counts and resource_name_counts[resource_name] > 5
    is_common_type = resource_type in resource_type_counts and resource_type_counts[resource_type] > 10
    
    # 점수 계산
    if is_frequent_resource:
        # 자주 접근하는 리소스
        score = 0
        message = "자주 접근하는 리소스입니다."
    elif is_common_type:
        # 일반적인 유형의 리소스지만 특정 리소스는 새로움
        score = 20
        message = "일반적인 유형의 새로운 리소스입니다."
    else:
        # 완전히 새로운 유형의 리소스
        score = 40
        message = "새로운 유형의 리소스입니다."
    
    return {
        "type": "resource_pattern",
        "score": score,
        "resource": resource,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "is_frequent": is_frequent_resource,
        "is_common_type": is_common_type,
        "message": message
    }

def analyze_action_sequence(action, recent_actions, profile):
    """
    액션 시퀀스가 사용자의 일반적인 행동 패턴에 맞는지 분석
    """
    # 프로파일에서 일반적인 액션 시퀀스 가져오기
    action_sequences = profile.get("action_sequences", {})
    top_sequences = action_sequences.get("top_sequences", {})
    
    # 최근 액션이 없는 경우
    if not recent_actions:
        return {
            "type": "action_sequence",
            "score": 15,  # 약간의 의심
            "message": "이전 액션 컨텍스트가 없습니다.",
            "matches_sequence": False
        }
    
    # 가장 최근 액션
    last_action = recent_actions[-1]
    
    # 시퀀스 확인
    sequence = f"{last_action} -> {action}"
    is_common_sequence = sequence in top_sequences
    
    # 점수 계산
    if is_common_sequence:
        # 일반적인 액션 시퀀스
        score = 0
        message = "일반적인 액션 시퀀스입니다."
    else:
        # 비정상적인 액션 시퀀스
        score = 25
        message = "일반적이지 않은 액션 시퀀스입니다."
    
    return {
        "type": "action_sequence",
        "score": score,
        "sequence": sequence,
        "matches_sequence": is_common_sequence,
        "message": message
    }

def evaluate_resource_sensitivity(resource, action):
    """
    리소스 및 액션의 민감도 평가
    
    Args:
        resource (str): 접근 대상 리소스
        action (str): 요청된 액션
        
    Returns:
        dict: 리소스 민감도 점수 및 세부 정보
    """
    # 기본 점수
    base_score = 0
    sensitivity_level = "low"
    factors = []
    
    # 민감한 서비스 및 리소스 타입 확인
    sensitive_services = {
        "iam": 50,        # IAM은 매우 민감
        "kms": 40,        # 암호화 키도 매우 민감
        "secretsmanager": 40,  # 비밀 관리
        "rds": 30,        # 데이터베이스
        "dynamodb": 25,   # NoSQL 데이터베이스
        "ec2": 20,        # 컴퓨팅 리소스
        "lambda": 20,     # 서버리스 함수
        "s3": 15          # 스토리지 (민감도는 버킷/객체에 따라 다름)
    }
    
    # ARN에서 서비스 추출
    service = "unknown"
    if resource.startswith("arn:aws:"):
        parts = resource.split(":")
        if len(parts) >= 3:
            service = parts[2]
    
    # 서비스 민감도 점수 추가
    if service in sensitive_services:
        sensitivity_score = sensitive_services[service]
        base_score += sensitivity_score
        factors.append({
            "type": "sensitive_service",
            "service": service,
            "score": sensitivity_score,
            "message": f"{service}는 민감한 서비스입니다."
        })
    
    # 액션 유형에 따른 점수 추가
    action_verbs = {
        "Create": 20,
        "Delete": 30,
        "Update": 25,
        "Put": 20,
        "Modify": 25,
        "Stop": 30,
        "Start": 15,
        "Terminate": 35,
        "Get": 5,
        "List": 5,
        "Describe": 5
    }
    
    # 액션에서 동사 추출
    verb = None
    if ":" in action:
        _, api = action.split(":", 1)
        for v in action_verbs.keys():
            if api.startswith(v):
                verb = v
                break
    
    # 액션 민감도 점수 추가
    if verb and verb in action_verbs:
        verb_score = action_verbs[verb]
        base_score += verb_score
        factors.append({
            "type": "action_sensitivity",
            "verb": verb,
            "score": verb_score,
            "message": f"{verb} 작업은 {verb_score}점의 민감도를 가집니다."
        })
    
    # 특별히 민감한 리소스 패턴 확인
    sensitive_patterns = [
        {"pattern": "prod", "score": 20, "message": "프로덕션 환경 리소스"},
        {"pattern": "admin", "score": 25, "message": "관리자 리소스"},
        {"pattern": "master", "score": 25, "message": "마스터/주요 리소스"},
        {"pattern": "secret", "score": 30, "message": "비밀 정보 리소스"},
        {"pattern": "password", "score": 35, "message": "패스워드 관련 리소스"},
        {"pattern": "key", "score": 25, "message": "키 관련 리소스"},
        {"pattern": "finance", "score": 30, "message": "재무 관련 리소스"},
        {"pattern": "customer", "score": 25, "message": "고객 데이터 리소스"},
        {"pattern": "pii", "score": 35, "message": "개인식별정보 리소스"}
    ]
    
    # 리소스 이름에서 민감한 패턴 확인
    resource_lower = resource.lower()
    for pattern in sensitive_patterns:
        if pattern["pattern"] in resource_lower:
            pattern_score = pattern["score"]
            base_score += pattern_score
            factors.append({
                "type": "sensitive_pattern",
                "pattern": pattern["pattern"],
                "score": pattern_score,
                "message": pattern["message"]
            })
    
    # 최종 민감도 수준 결정
    if base_score >= 70:
        sensitivity_level = "critical"
    elif base_score >= 50:
        sensitivity_level = "high"
    elif base_score >= 30:
        sensitivity_level = "medium"
    else:
        sensitivity_level = "low"
    
    return {
        "score": min(100, base_score),  # 최대 100점
        "sensitivity_level": sensitivity_level,
        "factors": factors
    }

def calculate_risk_score(context_score, behavior_score, resource_score):
    """
    컨텍스트, 행동, 리소스 점수를 종합하여 전체 위험 점수 계산
    
    Args:
        context_score (dict): 컨텍스트 검증 결과
        behavior_score (dict): 행동 패턴 분석 결과
        resource_score (dict): 리소스 민감도 평가 결과
        
    Returns:
        int: 최종 위험 점수 (0-100)
    """
    # 가중치 설정
    context_weight = 0.4    # 컨텍스트 40%
    behavior_weight = 0.35   # 행동 패턴 35%
    resource_weight = 0.25   # 리소스 민감도 25%
    
    # 각 항목의 점수 추출
    context_value = context_score.get("score", 50)
    behavior_value = behavior_score.get("score", 50)
    resource_value = resource_score.get("score", 50)
    
    # 가중 평균 계산
    weighted_score = (
        context_value * context_weight +
        behavior_value * behavior_weight +
        resource_value * resource_weight
    )
    
    # 점수 반올림
    return round(weighted_score)