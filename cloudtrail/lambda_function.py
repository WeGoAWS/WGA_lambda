# lambda_functions/cloudtrail/lambda_function.py
import json
import os
import time
from common.db import get_session
from common.config import CONFIG
from common.utils import extract_session_id_from_cookies, format_api_response, handle_api_exception, get_aws_session
from cloudtrail_service import get_cloudtrail_events, get_active_cloudtrail_s3_buckets, process_daily_logs, analyze_user_activity

def lambda_handler(event, context):
    """
    Lambda 핸들러 함수
    """
    print(f"Received event: {json.dumps(event)}")
    
    # API Gateway에서 요청 경로 및 HTTP 메서드 추출
    path = event.get('path', '/')
    http_method = event.get('httpMethod', 'GET')
    
    # 엔드포인트 라우팅
    try:
        if path == '/cloudtrail/logs' and http_method == 'GET':
            return get_cloudtrail_logs(event)
        elif path == '/cloudtrail/analyze-logs' and http_method == 'GET':
            return analyze_cloudtrail_logs(event)
        else:
            return format_api_response(404, {'error': 'Not Found'})
    except Exception as e:
        return handle_api_exception(e)

def get_cloudtrail_logs(event):
    """
    로그인한 사용자의 인증 정보를 이용하여 CloudTrail 로그 조회
    """
    try:
        # 쿼리 파라미터에서 max_results 추출
        query_params = event.get('queryStringParameters', {}) or {}
        max_results = int(query_params.get('max_results', 50))
        
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return format_api_response(401, {"detail": "ID token not found."})
        
        # 임시 AWS 세션 얻기
        session = get_aws_session(id_token)
        
        # cloudtrail_service의 래퍼 함수 활용
        logs_summary = get_cloudtrail_logs_summary(session, max_results)
        
        return format_api_response(200, logs_summary)
    except Exception as e:
        return handle_api_exception(e)

def analyze_cloudtrail_logs(event):
    """
    CloudTrail 로그 분석 실행
    """
    try:
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return format_api_response(401, {"detail": "ID token not found."})
            
        # AWS 세션 생성
        session = get_aws_session(id_token)
        
        # 사용자 컨텍스트 정보 (필요한 경우)
        user_context = {
            'source_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', ''),
            'user_agent': event.get('headers', {}).get('User-Agent', '')
        }
        
        # cloudtrail_service의 래퍼 함수 활용
        result = analyze_cloudtrail_with_context(session, id_token, user_context)
        
        return format_api_response(200, result)
    except Exception as e:
        return handle_api_exception(e)

def get_id_token_from_session(event):
    """
    요청의 세션 쿠키에서 ID 토큰을 추출합니다.
    """
    # 쿠키에서 세션 ID 추출
    cookies = event.get('headers', {}).get('Cookie', '')
    session_id = extract_session_id_from_cookies(cookies)
    
    if not session_id:
        return None
    
    # 세션 정보 조회
    session = get_session(session_id)
    
    # 세션에서 ID 토큰 반환
    return session.get('id_token') if session else None