# 4. 이상 탐지 Lambda 함수 (anomaly_detector/lambda_function.py)

import json
import boto3
import time
import datetime
from common.config import CONFIG
from common.db import create_analysis_result
from common.utils import extract_session_id_from_cookies, format_api_response, handle_api_exception, get_aws_session
from detector_service import detect_account_anomalies, get_user_risk_score, save_anomaly_event

def lambda_handler(event, context):
    """
    Lambda 핸들러 함수 - 이상 행동 탐지
    """
    print(f"Received event: {json.dumps(event)}")
    
    # API Gateway에서 요청 경로 및 HTTP 메서드 추출
    path = event.get('path', '/')
    http_method = event.get('httpMethod', 'GET')
    
    # 엔드포인트 라우팅
    try:
        if path == '/anomaly-detector/detect-account-anomalies' and http_method == 'GET':
            return detect_account_anomalies_handler(event)
        elif path == '/anomaly-detector/get-user-risk-score' and http_method == 'GET':
            return get_user_risk_score_handler(event)
        else:
            return format_api_response(404, {'error': 'Not Found'})
    except Exception as e:
        return handle_api_exception(e)

def detect_account_anomalies_handler(event):
    """
    AWS 계정 전체에 대한 이상 행동 탐지
    """
    try:
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return format_api_response(401, {"detail": "인증이 필요합니다."})
        
        # AWS 세션 생성
        session = get_aws_session(id_token)
        
        # 쿼리 파라미터에서 기간 추출
        query_params = event.get('queryStringParameters', {}) or {}
        days = int(query_params.get('days', 7))
        
        # 계정 전체 이상 탐지 실행
        results = detect_account_anomalies(session, days)
        
        return format_api_response(200, results)
    except Exception as e:
        return handle_api_exception(e)

def get_user_risk_score_handler(event):
    """
    특정 사용자의 위험 점수 계산
    """
    try:
        # 쿼리 파라미터에서 사용자 ARN 추출
        query_params = event.get('queryStringParameters', {}) or {}
        user_arn = query_params.get('user_arn')
        
        if not user_arn:
            return format_api_response(400, {"detail": "사용자 ARN이 필요합니다."})
        
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return format_api_response(401, {"detail": "인증이 필요합니다."})
        
        # AWS 세션 생성
        session = get_aws_session(id_token)
        
        # 사용자 위험 점수 계산
        risk_score = get_user_risk_score(session, user_arn)
        
        return format_api_response(200, risk_score)
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