#!/bin/bash
# Lambda 배포 스크립트

set -e

# 현재 사용 중인 AWS 자격 증명 확인
echo "현재 사용 중인 AWS 자격 증명 정보:"
aws sts get-caller-identity

# 기본 설정 변수
ENV=${1:-dev}
REGION=${2:-us-east-1}
S3_BUCKET="wga-lambda-deployment"

# 색상 코드
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}WGA Lambda 함수 배포 스크립트 - 환경: ${ENV}, 리전: ${REGION}${NC}"

# S3 버킷 존재 확인 및 생성
if ! aws s3 ls "s3://${S3_BUCKET}" --region ${REGION} 2>&1 > /dev/null; then
    echo -e "${YELLOW}S3 버킷 ${S3_BUCKET}이 존재하지 않습니다. 생성합니다...${NC}"
    aws s3 mb "s3://${S3_BUCKET}" --region ${REGION}
    # 버킷 버전 관리 활성화
    aws s3api put-bucket-versioning --bucket ${S3_BUCKET} --versioning-configuration Status=Enabled --region ${REGION}
else
    echo -e "${GREEN}S3 버킷 ${S3_BUCKET}이 이미 존재합니다.${NC}"
fi

# 출력용 S3 버킷 확인 및 생성
OUTPUT_BUCKET="wga-outputbucket"
if ! aws s3 ls "s3://${OUTPUT_BUCKET}" --region ${REGION} 2>&1 > /dev/null; then
    echo -e "${YELLOW}S3 버킷 ${OUTPUT_BUCKET}이 존재하지 않습니다. 생성합니다...${NC}"
    aws s3 mb "s3://${OUTPUT_BUCKET}" --region ${REGION}
    # 버킷 버전 관리 활성화
    aws s3api put-bucket-versioning --bucket ${OUTPUT_BUCKET} --versioning-configuration Status=Enabled --region ${REGION}
else
    echo -e "${GREEN}S3 버킷 ${OUTPUT_BUCKET}이 이미 존재합니다.${NC}"
fi

# 임시 디렉토리 생성
TEMP_DIR=$(mktemp -d)
echo -e "${GREEN}임시 디렉토리 생성: ${TEMP_DIR}${NC}"

# 공통 모듈 준비
mkdir -p ${TEMP_DIR}/common
echo -e "${GREEN}공통 모듈 복사...${NC}"
cp -r common/* ${TEMP_DIR}/common/

# 함수별 배포 패키지 생성 및 업로드
for func in auth cloudtrail policy-recommendation user_behavior_analytics role_manager zero_trust_enforcer anomaly_detector; do
    echo -e "${YELLOW}함수 ${func} 배포 패키지 생성 중...${NC}"
    
    # 함수별 디렉토리 생성
    FUNC_DIR=${TEMP_DIR}/${func}
    mkdir -p ${FUNC_DIR}
    
    # 함수 코드 복사
    cp -r ${func}/* ${FUNC_DIR}/
    
    # CloudTrail 함수의 파일명 오류 수정
    if [ "$func" = "cloudtrail" ] && [ -f "${FUNC_DIR}/lambda_funciton.py" ]; then
        echo -e "${RED}CloudTrail 함수의 파일명 오류 발견. 수정합니다...${NC}"
        mv "${FUNC_DIR}/lambda_funciton.py" "${FUNC_DIR}/lambda_function.py"
    fi
    
    # 공통 모듈 복사
    mkdir -p ${FUNC_DIR}/common
    cp -r ${TEMP_DIR}/common/* ${FUNC_DIR}/common/
    
    # 현재 디렉토리로 이동
    cd ${FUNC_DIR}
    
    # pip로 의존성 설치
    if [ -f "requirements.txt" ]; then
        echo -e "${GREEN}의존성 패키지 설치 중...${NC}"
        pip install -r requirements.txt -t .
    fi
    
    # 배포 패키지 생성 (ZIP)
    echo -e "${GREEN}ZIP 파일 생성 중...${NC}"
    zip -q -r ${TEMP_DIR}/wga-${func}.zip .
    
    # 원래 디렉토리로 돌아가기
    cd - > /dev/null
    
    # S3에 업로드 (새 버전 생성을 위해 임의 날짜 추가)
    echo -e "${GREEN}S3에 업로드 중...${NC}"
    TIMESTAMP=$(date +%Y%m%d%H%M%S)
    aws s3 cp ${TEMP_DIR}/wga-${func}.zip s3://${S3_BUCKET}/wga-${func}-${TIMESTAMP}.zip --region ${REGION}
    
    # 새 파일명을 적용하도록 파라미터 파일 수정 (jq 사용)
    if [ -x "$(command -v jq)" ] && [ -f "parameters-${ENV}.json" ]; then
        # 파일명 매핑
        if [ "$func" = "auth" ]; then
            S3_KEY="wga-auth-${TIMESTAMP}.zip"
            jq --arg key "$S3_KEY" 'map(if .ParameterKey == "AuthCodeKey" then .ParameterValue = $key else . end)' parameters-${ENV}.json > ${TEMP_DIR}/params-temp.json
            mv ${TEMP_DIR}/params-temp.json parameters-${ENV}.json
        elif [ "$func" = "cloudtrail" ]; then
            S3_KEY="wga-cloudtrail-${TIMESTAMP}.zip"
            jq --arg key "$S3_KEY" 'map(if .ParameterKey == "CloudTrailCodeKey" then .ParameterValue = $key else . end)' parameters-${ENV}.json > ${TEMP_DIR}/params-temp.json
            mv ${TEMP_DIR}/params-temp.json parameters-${ENV}.json
        elif [ "$func" = "policy-recommendation" ]; then
            S3_KEY="wga-policy-recommendation-${TIMESTAMP}.zip"
            jq --arg key "$S3_KEY" 'map(if .ParameterKey == "PolicyRecommendationCodeKey" then .ParameterValue = $key else . end)' parameters-${ENV}.json > ${TEMP_DIR}/params-temp.json
            mv ${TEMP_DIR}/params-temp.json parameters-${ENV}.json
        fi
        echo -e "${GREEN}파라미터 파일에 코드 키 업데이트: ${S3_KEY}${NC}"
    fi
    
    echo -e "${GREEN}함수 ${func} 배포 패키지 업로드 완료!${NC}"
done

# 기본 키를 사용하는 심볼릭 링크 생성
aws s3 cp ${TEMP_DIR}/wga-auth.zip s3://${S3_BUCKET}/wga-auth.zip --region ${REGION}
aws s3 cp ${TEMP_DIR}/wga-cloudtrail.zip s3://${S3_BUCKET}/wga-cloudtrail.zip --region ${REGION}
aws s3 cp ${TEMP_DIR}/wga-policy-recommendation.zip s3://${S3_BUCKET}/wga-policy-recommendation.zip --region ${REGION}

# CloudFormation 템플릿 업로드
echo -e "${YELLOW}CloudFormation 템플릿 업로드 중...${NC}"
aws s3 cp cloudformation-template.yaml s3://${S3_BUCKET}/ --region ${REGION}

# CloudFormation 스택 배포
echo -e "${YELLOW}CloudFormation 스택 배포 중...${NC}"

# 환경에 맞는 파라미터 파일 로드
if [ -f "parameters-${ENV}.json" ]; then
    PARAMS_FILE="parameters-${ENV}.json"
    echo -e "${GREEN}파라미터 파일 사용: ${PARAMS_FILE}${NC}"
    
    # jq가 설치되어 있는지 확인
    if [ -x "$(command -v jq)" ]; then
        # 현재 타임스탬프 생성
        TIMESTAMP=$(date +%Y%m%d%H%M%S)
        echo -e "${GREEN}배포 타임스탬프: ${TIMESTAMP}${NC}"
        
        # 임시 파일 생성
        TMP_PARAMS=$(mktemp)
        
        # DeploymentTimestamp 파라미터 업데이트 및 DeploymentBucketName 추가
        jq --arg bucket "$S3_BUCKET" --arg ts "$TIMESTAMP" '
            map(if .ParameterKey == "DeploymentTimestamp" then .ParameterValue = $ts else . end) |
            . += [{"ParameterKey": "DeploymentBucketName", "ParameterValue": $bucket}]
        ' ${PARAMS_FILE} > ${TMP_PARAMS}
        
        PARAMS_FILE=${TMP_PARAMS}
        echo -e "${GREEN}DeploymentTimestamp 파라미터가 ${TIMESTAMP}로 업데이트되었습니다.${NC}"
    else
        echo -e "${YELLOW}jq가 설치되어 있지 않습니다. DeploymentBucketName과 DeploymentTimestamp 파라미터를 수동으로 추가해주세요.${NC}"
    fi
    
    # 템플릿 유효성 검사
    echo -e "${GREEN}CloudFormation 템플릿 유효성 검사 중...${NC}"
    aws cloudformation validate-template \
        --template-url https://${S3_BUCKET}.s3.${REGION}.amazonaws.com/cloudformation-template.yaml \
        --region ${REGION}
        
    # 스택이 존재하는지 확인
    if aws cloudformation describe-stacks --stack-name wga-lambda-${ENV} --region ${REGION} &>/dev/null; then
        # 스택 업데이트 및 완료 대기
        echo -e "${GREEN}기존 스택 업데이트 중...${NC}"
        aws cloudformation update-stack \
            --stack-name wga-lambda-${ENV} \
            --template-url https://${S3_BUCKET}.s3.${REGION}.amazonaws.com/cloudformation-template.yaml \
            --parameters file://${PARAMS_FILE} \
            --capabilities CAPABILITY_NAMED_IAM \
            --region ${REGION}
            
        echo -e "${YELLOW}스택 업데이트 완료 대기 중...${NC}"
        if aws cloudformation wait stack-update-complete --stack-name wga-lambda-${ENV} --region ${REGION}; then
            echo -e "${GREEN}스택 업데이트 완료!${NC}"
        else
            echo -e "${RED}스택 업데이트 실패! 이벤트 로그를 확인합니다:${NC}"
            aws cloudformation describe-stack-events \
                --stack-name wga-lambda-${ENV} \
                --region ${REGION} \
                --query "StackEvents[?contains(ResourceStatus, 'FAILED')].{Resource:LogicalResourceId, Status:ResourceStatus, Reason:ResourceStatusReason}" \
                --output table
        fi
    else
        # 스택 생성 및 완료 대기
        echo -e "${GREEN}새 스택 생성 중...${NC}"
        aws cloudformation create-stack \
            --stack-name wga-lambda-${ENV} \
            --template-url https://${S3_BUCKET}.s3.${REGION}.amazonaws.com/cloudformation-template.yaml \
            --parameters file://${PARAMS_FILE} \
            --capabilities CAPABILITY_NAMED_IAM \
            --region ${REGION}
            
        echo -e "${YELLOW}스택 생성 완료 대기 중...${NC}"
        if aws cloudformation wait stack-create-complete --stack-name wga-lambda-${ENV} --region ${REGION}; then
            echo -e "${GREEN}스택 생성 완료!${NC}"
        else
            echo -e "${RED}스택 생성 실패! 이벤트 로그를 확인합니다:${NC}"
            aws cloudformation describe-stack-events \
                --stack-name wga-lambda-${ENV} \
                --region ${REGION} \
                --query "StackEvents[?contains(ResourceStatus, 'FAILED')].{Resource:LogicalResourceId, Status:ResourceStatus, Reason:ResourceStatusReason}" \
                --output table
        fi
    fi

    # 임시 디렉토리 제거
    echo -e "${GREEN}임시 디렉토리 정리 중...${NC}"
    rm -rf ${TEMP_DIR}  
    
    # 배포 완료 후 API 엔드포인트 정보 출력
    echo -e "${YELLOW}스택 정보 조회 중...${NC}"
    API_ENDPOINT=$(aws cloudformation describe-stacks --stack-name wga-lambda-${ENV} --region ${REGION} --query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue" --output text)

    if [ "$API_ENDPOINT" = "None" ] || [ -z "$API_ENDPOINT" ]; then
        echo -e "${YELLOW}API 엔드포인트를 찾을 수 없습니다. 다음 명령으로 모든 출력값을 확인하세요:${NC}"
        echo -e "aws cloudformation describe-stacks --stack-name wga-lambda-${ENV} --region ${REGION} --query \"Stacks[0].Outputs\" --output json"
    else
        echo -e "${GREEN}배포 완료!${NC}"
        echo -e "${GREEN}API 엔드포인트: ${API_ENDPOINT}${NC}"
    fi
fi