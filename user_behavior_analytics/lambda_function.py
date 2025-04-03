# 1. 사용자 행동 분석 Lambda 함수 (user_behavior_analytics/lambda_function.py)

import json
import boto3
import time
import datetime
import numpy as np
from common.config import CONFIG
from common.db import create_analysis_result
from common.utils import extract_session_id_from_cookies, format_api_response, handle_api_exception, get_aws_session
from behavior_analytics_service import analyze_user_behavior, detect_anomalies, update_user_profile

def lambda_handler(event, context):
    """
    Lambda 핸들러 함수 - 사용자 행동 분석
    """
    print(f"Received event: {json.dumps(event)}")
    
    # API Gateway에서 요청 경로 및 HTTP 메서드 추출
    path = event.get('path', '/')
    http_method = event.get('httpMethod', 'GET')
    
    # 엔드포인트 라우팅
    try:
        if path == '/behavior-analytics/analyze-user' and http_method == 'GET':
            return analyze_user_behavior_handler(event)
        elif path == '/behavior-analytics/detect-anomalies' and http_method == 'POST':
            return detect_anomalies_handler(event)
        else:
            return format_api_response(404, {'error': 'Not Found'})
    except Exception as e:
        return handle_api_exception(e)

def analyze_user_behavior_handler(event):
    """
    특정 사용자의 행동 패턴을 분석하고 프로파일 업데이트
    """
    try:
        # 쿼리 파라미터에서 사용자 ARN 추출
        query_params = event.get('queryStringParameters', {}) or {}
        user_arn = query_params.get('user_arn')
        days = int(query_params.get('days', 30))
        
        if not user_arn:
            return format_api_response(400, {"detail": "사용자 ARN이 필요합니다."})
        
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return format_api_response(401, {"detail": "인증이 필요합니다."})
        
        # AWS 세션 생성
        session = get_aws_session(id_token)
        
        # 사용자 행동 분석 수행
        analysis_result = analyze_user_behavior(session, user_arn, days)
        
        # 사용자 프로파일 업데이트
        profile_updated = update_user_profile(user_arn, analysis_result)
        
        # 분석 결과에 프로파일 업데이트 상태 추가
        analysis_result['profile_updated'] = profile_updated
        
        return format_api_response(200, analysis_result)
    except Exception as e:
        return handle_api_exception(e)

def detect_anomalies_handler(event):
    """
    사용자 행동 분석을 통해 이상 패턴 감지
    """
    try:
        # 요청 바디 파싱
        body = json.loads(event.get('body', '{}'))
        user_arn = body.get('user_arn')
        cloudtrail_event = body.get('cloudtrail_event')
        
        if not user_arn or not cloudtrail_event:
            return format_api_response(400, {"detail": "사용자 ARN과 CloudTrail 이벤트가 필요합니다."})
        
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return format_api_response(401, {"detail": "인증이 필요합니다."})
        
        # AWS 세션 생성
        session = get_aws_session(id_token)
        
        # 이상 행동 탐지
        anomaly_result = detect_anomalies(session, user_arn, cloudtrail_event)
        
        # 결과에 따라 알림 생성 (위험 점수가 높은 경우)
        if anomaly_result.get('risk_score', 0) > 70:
            send_anomaly_alert(session, user_arn, anomaly_result)
        
        return format_api_response(200, anomaly_result)
    except Exception as e:
        return handle_api_exception(e)

def get_id_token_from_session(event):
    """
    요청의 세션 쿠키에서 ID 토큰을 추출합니다.
    """
    # 쿠키에서 세션 ID 추출
    headers = event.get('headers', {})
    cookies = headers.get('Cookie', '') or headers.get('cookie', '')
    
    session_id = extract_session_id_from_cookies(cookies)
    
    if not session_id:
        return None
    
    # 세션 정보 조회
    from common.db import get_session
    session = get_session(session_id)
    
    # 세션에서 ID 토큰 반환
    id_token = session.get('id_token') if session else None
    
    return id_token

def send_anomaly_alert(session, user_arn, anomaly_result):
    """
    이상 행동 탐지 시 SNS를 통해 알림 발송
    """
    sns_client = session.client('sns')
    
    # 알림 메시지 구성
    message = {
        'user_arn': user_arn,
        'risk_score': anomaly_result.get('risk_score', 0),
        'anomaly_type': anomaly_result.get('anomaly_type', 'Unknown'),
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'details': anomaly_result.get('details', {}),
        'recommended_action': anomaly_result.get('recommended_action', 'Investigate')
    }
    
    # SNS 토픽에 알림 발송
    try:
        sns_client.publish(
            TopicArn=CONFIG['sns']['anomaly_alert_topic'],
            Message=json.dumps(message),
            Subject=f"Security Alert: Anomaly detected for {user_arn}"
        )
        print(f"Anomaly alert sent for user: {user_arn}")
        return True
    except Exception as e:
        print(f"Error sending anomaly alert: {e}")
        return False