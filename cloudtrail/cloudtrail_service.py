# lambda_functions/cloudtrail/cloudtrail_service.py
import os
import json
import datetime
import boto3
import gzip
import tempfile
import uuid
from io import BytesIO
from common.config import CONFIG
from common.utils import get_aws_session, upload_to_s3
from common.db import save_anomaly_event

def get_cloudtrail_events(session, max_results=50, start_time=None, end_time=None):
    """
    CloudTrail 이벤트를 조회합니다.
    
    Args:
        session (boto3.Session): AWS 세션
        max_results (int): 최대 결과 개수
        start_time (datetime): 조회 시작 시간
        end_time (datetime): 조회 종료 시간
        
    Returns:
        list: CloudTrail 이벤트 목록
    """
    cloudtrail_client = session.client("cloudtrail")
    
    # 조회 파라미터 구성
    params = {
        "MaxResults": max_results
    }
    
    # 시간 범위 설정
    if start_time and end_time:
        params["StartTime"] = start_time
        params["EndTime"] = end_time
    
    try:
        events_response = cloudtrail_client.lookup_events(**params)
        events = events_response.get("Events", [])
        
        return events
    except Exception as e:
        print(f"Error looking up CloudTrail events: {e}")
        raise

def get_active_cloudtrail_s3_buckets(session):
    """
    CloudTrail이 활성화된 S3 버킷 목록을 가져옵니다.
    
    Args:
        session (boto3.Session): AWS 세션
        
    Returns:
        list: S3 버킷 이름 목록
    """
    cloudtrail_client = session.client("cloudtrail")

    try:
        trails = cloudtrail_client.describe_trails().get("trailList", [])
    except Exception as e:
        raise Exception(f"CloudTrail access error: {str(e)}")

    active_buckets = []
    for trail in trails:
        s3_bucket = trail.get("S3BucketName")
        if s3_bucket:
            try:
                # 각 트레일의 상태를 확인하여 로깅이 활성화되어 있는지 체크
                status = cloudtrail_client.get_trail_status(Name=trail.get("Name"))
                if status.get("IsLogging"):
                    active_buckets.append(s3_bucket)
            except Exception:
                # 개별 트레일 상태 조회 실패 시 해당 트레일은 건너뜁니다.
                continue

    return active_buckets

def download_cloudtrail_logs(session, bucket_name, prefix, max_files=10):
    """
    S3 버킷에서 CloudTrail 로그 파일을 다운로드합니다.
    
    Args:
        session (boto3.Session): AWS 세션
        bucket_name (str): S3 버킷 이름
        prefix (str): 객체 접두사
        max_files (int): 최대 다운로드 파일 수
        
    Returns:
        list: 다운로드한 로그 이벤트 목록
    """
    s3_client = session.client('s3')
    
    # S3 객체 목록 조회
    try:
        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=prefix,
            MaxKeys=max_files
        )
    except Exception as e:
        print(f"Error listing S3 objects: {e}")
        raise
    
    if 'Contents' not in response:
        return []
    
    # 모든 로그 이벤트 저장 리스트
    all_log_events = []
    
    # 각 로그 파일 처리
    for obj in response['Contents']:
        key = obj['Key']
        
        try:
            # S3 객체 가져오기
            response = s3_client.get_object(Bucket=bucket_name, Key=key)
            content = response['Body'].read()
            
            # gzip 압축 여부 확인 및 압축 해제
            if key.endswith('.gz') or response.get('ContentType') == 'application/gzip':
                with gzip.GzipFile(fileobj=BytesIO(content), mode='rb') as f:
                    decompressed_content = f.read()
                log_data = json.loads(decompressed_content)
            else:
                log_data = json.loads(content)
            
            # 'Records' 키가 있는 경우 해당 목록 추가
            if isinstance(log_data, dict) and 'Records' in log_data:
                all_log_events.extend(log_data['Records'])
            else:
                all_log_events.append(log_data)
            
        except Exception as e:
            print(f"Error processing log file {key}: {e}")
            continue
    
    return all_log_events

def process_daily_logs(session, id_token):
    """
    최근 하루의 CloudTrail 로그를 처리하고 결과를 S3에 저장합니다.
    
    Args:
        session (boto3.Session): AWS 세션
        id_token (str): ID 토큰
        
    Returns:
        dict: 처리 결과 요약
    """
    # 활성 CloudTrail 버킷 목록 가져오기
    s3_buckets = get_active_cloudtrail_s3_buckets(session)
    
    if not s3_buckets:
        return {
            "status": "error",
            "message": "활성화된 CloudTrail S3 버킷을 찾을 수 없습니다."
        }
    
    # 현재 날짜 정보
    now = datetime.datetime.utcnow()
    yesterday = now - datetime.timedelta(days=1)
    date_prefix = yesterday.strftime('%Y/%m/%d')
    
    # 계정 ID 가져오기
    sts_client = session.client('sts')
    account_id = sts_client.get_caller_identity()["Account"]
    
    all_logs = []
    processed_buckets = []
    errors = []
    
    # 각 버킷에서 로그 처리
    for bucket_name in s3_buckets:
        try:
            # CloudTrail 로그의 일반적인 경로 형식
            prefix = f"AWSLogs/{account_id}/CloudTrail/{CONFIG['aws_region']}/{date_prefix}/"
            
            logs = download_cloudtrail_logs(session, bucket_name, prefix, max_files=5)
            all_logs.extend(logs)
            processed_buckets.append(bucket_name)
        except Exception as e:
            errors.append({
                "bucket": bucket_name,
                "error": str(e)
            })
    
    try:
        # User Behavior Analytics Lambda 호출
        lambda_client = session.client('lambda')
        
        # 분석할 사용자 ARN 목록
        user_arns = extract_unique_users(all_logs)
        
        for user_arn in user_arns:
            # 사용자별 행동 분석 실행
            payload = {
                'user_arn': user_arn,
                'days': 1  # 최근 1일 분석
            }
            
            lambda_client.invoke(
                FunctionName=f'wga-user-behavior-analytics-{CONFIG["env"]}',
                InvocationType='Event',  # 비동기 호출
                Payload=json.dumps(payload)
            )
            
            print(f"Triggered behavior analysis for user: {user_arn}")
    except Exception as e:
        print(f"Error triggering behavior analysis: {e}")
    
    # 결과 저장
    if all_logs:
        # 간단한 분석 결과 준비 (실제 분석은 별도 서비스에서 수행)
        result = {
            "date": yesterday.strftime('%Y-%m-%d'),
            "account_id": account_id,
            "log_count": len(all_logs),
            "analysis_timestamp": now.isoformat() + "Z",
            "processed_buckets": processed_buckets,
            "errors": errors
        }
        
        # 결과 파일 경로
        output_key = f"results/{yesterday.strftime('%Y-%m-%d')}-analysis-{uuid.uuid4()}.json"
        
        # S3에 결과 업로드
        upload_to_s3(session, CONFIG['s3']['output_bucket'], output_key, result)
        
        return {
            "status": "success",
            "message": f"로그 분석 완료. 총 {len(all_logs)}개 로그 처리됨.",
            "result_path": f"s3://{CONFIG['s3']['output_bucket']}/{output_key}",
            "processed_buckets": processed_buckets,
            "errors": errors
        }
    else:
        return {
            "status": "warning",
            "message": "처리할 로그를 찾을 수 없습니다.",
            "processed_buckets": processed_buckets,
            "errors": errors
        }

def analyze_user_activity(session, user_arn, days=7):
    """
    특정 사용자의 활동을 분석합니다.
    
    Args:
        session (boto3.Session): AWS 세션
        user_arn (str): 분석할 사용자 ARN
        days (int): 분석할 기간(일)
        
    Returns:
        dict: 분석 결과
    """
    cloudtrail_client = session.client("cloudtrail")
    
    # 시간 범위 설정
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(days=days)
    
    # 이벤트 조회 파라미터
    params = {
        "LookupAttributes": [
            {
                "AttributeKey": "Username",
                "AttributeValue": user_arn
            }
        ],
        "StartTime": start_time,
        "EndTime": end_time,
        "MaxResults": 1000  # 최대 결과 수
    }
    
    try:
        # 이벤트 조회
        events_response = cloudtrail_client.lookup_events(**params)
        events = events_response.get("Events", [])
        
        # 이벤트 유형별 카운트
        event_counts = {}
        for event in events:
            event_name = event.get("EventName", "Unknown")
            if event_name in event_counts:
                event_counts[event_name] += 1
            else:
                event_counts[event_name] = 1
        
        # 상위 이벤트 계산
        top_events = sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # 결과 구성
        result = {
            "user_arn": user_arn,
            "period_days": days,
            "total_events": len(events),
            "top_events": top_events,
            "event_counts": event_counts,
            "analysis_time": datetime.datetime.utcnow().isoformat() + "Z"
        }
        
        return result
    except Exception as e:
        print(f"Error analyzing user activity: {e}")
        raise

# lambda_functions/cloudtrail/cloudtrail_service.py에 래퍼 함수 추가

def get_cloudtrail_logs_summary(session, max_results=50):
    """
    CloudTrail 로그 이벤트를 조회하고 간략한 요약을 반환하는 래퍼 함수
    
    Args:
        session (boto3.Session): AWS 세션
        max_results (int): 최대 결과 개수
        
    Returns:
        dict: 로그 이벤트 요약 정보
    """
    try:
        # 기존 함수 활용
        events = get_cloudtrail_events(session, max_results)
        
        # 이벤트 타입별 카운팅
        event_types = {}
        for event in events:
            event_name = event.get('EventName', 'Unknown')
            if event_name in event_types:
                event_types[event_name] += 1
            else:
                event_types[event_name] = 1
        
        # 상위 이벤트 타입 계산
        top_events = sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'events': events,
            'total_events': len(events),
            'event_types_count': len(event_types),
            'top_events': top_events
        }
    except Exception as e:
        print(f"Error in get_cloudtrail_logs_summary: {e}")
        raise

def analyze_cloudtrail_with_context(session, id_token, user_context=None):
    """
    CloudTrail 로그 분석을 실행하고 컨텍스트 정보를 포함하는 래퍼 함수
    
    Args:
        session (boto3.Session): AWS 세션
        id_token (str): 사용자 ID 토큰
        user_context (dict, optional): 추가 사용자 컨텍스트
        
    Returns:
        dict: 분석 결과 및 컨텍스트 정보
    """
    # 기본 분석 실행
    analysis_result = process_daily_logs(session, id_token)
    
    # 활성 CloudTrail 버킷 정보 추가
    buckets = get_active_cloudtrail_s3_buckets(session)
    
    # 컨텍스트 정보 추가
    result = {
        **analysis_result,
        'context': {
            'active_cloudtrail_buckets': buckets,
            'analysis_timestamp': analysis_result.get('analysis_timestamp', ''),
            'user_context': user_context or {}
        }
    }
    
    return result

def extract_unique_users(logs):
    """
    CloudTrail 로그에서 고유한 사용자 ARN 목록을 추출합니다.
    """
    user_arns = set()
    
    for log in logs:
        username = log.get('userIdentity', {}).get('arn')
        if username and 'arn:aws:' in username:
            user_arns.add(username)
    
    return list(user_arns)

def invoke_behavior_analysis(session, analysis_result):
    """
    사용자 행동 분석 Lambda 비동기 호출
    """
    try:
        lambda_client = session.client('lambda')
        
        # 분석할 사용자 ARN 목록
        user_arns = set()
        
        # 결과에서 사용자 ARN 추출
        for bucket in analysis_result.get('processed_buckets', []):
            # CloudTrail 로그에서 사용자 ARN 추출 (세부 구현 필요)
            user_arns.update(extract_users_from_bucket(session, bucket))
        
        for user_arn in user_arns:
            # 사용자별 행동 분석 실행
            payload = {
                'queryStringParameters': {
                    'user_arn': user_arn,
                    'days': 7  # 최근 7일 분석
                }
            }
            
            lambda_client.invoke(
                FunctionName=f'wga-user-behavior-analytics-{CONFIG["env"]}',
                InvocationType='Event',  # 비동기 호출
                Payload=json.dumps(payload)
            )
            
            print(f"Triggered behavior analysis for user: {user_arn}")
    except Exception as e:
        print(f"Error triggering behavior analysis: {e}")

def invoke_anomaly_detection(session, analysis_result):
    """
    이상 탐지 Lambda 비동기 호출
    """
    try:
        lambda_client = session.client('lambda')
        
        # 계정 전체 이상 탐지 실행
        payload = {
            'queryStringParameters': {
                'days': 1  # 최근 1일 분석
            }
        }
        
        lambda_client.invoke(
            FunctionName=f'wga-anomaly-detector-{CONFIG["env"]}',
            InvocationType='Event',  # 비동기 호출
            Payload=json.dumps(payload)
        )
        
        print(f"Triggered account-wide anomaly detection")
    except Exception as e:
        print(f"Error triggering anomaly detection: {e}")