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
for func in auth cloudtrail policy-recommendation; do
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
    
    # S3에 업로드
    echo -e "${GREEN}S3에 업로드 중...${NC}"
    aws s3 cp ${TEMP_DIR}/wga-${func}.zip s3://${S3_BUCKET}/ --region ${REGION}
    
    echo -e "${GREEN}함수 ${func} 배포 패키지 업로드 완료!${NC}"
done

# CloudFormation 템플릿 업로드
echo -e "${YELLOW}CloudFormation 템플릿 업로드 중...${NC}"
aws s3 cp cloudformation-template.yaml s3://${S3_BUCKET}/ --region ${REGION}

# CloudFormation 스택 배포
echo -e "${YELLOW}CloudFormation 스택 배포 중...${NC}"

# 환경에 맞는 파라미터 파일 로드
if [ -f "parameters-${ENV}.json" ]; then
    PARAMS_FILE="parameters-${ENV}.json"
    echo -e "${GREEN}파라미터 파일 사용: ${PARAMS_FILE}${NC}"
    
    # 파라미터 파일에 DeploymentBucketName 추가
    # jq가 설치되어 있지 않을 경우 수동으로 파라미터 추가
    if [ -x "$(command -v jq)" ]; then
        # jq를 사용하여 DeploymentBucketName 파라미터 추가
        TMP_PARAMS=$(mktemp)
        jq --arg bucket "$S3_BUCKET" '
            . += [{"ParameterKey": "DeploymentBucketName", "ParameterValue": $bucket}]
        ' ${PARAMS_FILE} > ${TMP_PARAMS}
        PARAMS_FILE=${TMP_PARAMS}
    else
        echo -e "${YELLOW}jq가 설치되어 있지 않습니다. DeploymentBucketName 파라미터를 수동으로 추가해주세요.${NC}"
    fi
    
    # 템플릿 유효성 검사
    echo -e "${GREEN}CloudFormation 템플릿 유효성 검사 중...${NC}"
    aws cloudformation validate-template \
        --template-url https://${S3_BUCKET}.s3.${REGION}.amazonaws.com/cloudformation-template.yaml \
        --region ${REGION}
        
    # 스택이 존재하는지 확인
    if aws cloudformation describe-stacks --stack-name wga-lambda-${ENV} --region ${REGION} &>/dev/null; then
        # 스택 업데이트
        echo -e "${GREEN}기존 스택 업데이트 중...${NC}"
        aws cloudformation update-stack \
            --stack-name wga-lambda-${ENV} \
            --template-url https://${S3_BUCKET}.s3.${REGION}.amazonaws.com/cloudformation-template.yaml \
            --parameters file://${PARAMS_FILE} \
            --capabilities CAPABILITY_NAMED_IAM \
            --region ${REGION}
    else
        # 스택 생성
        echo -e "${GREEN}새 스택 생성 중...${NC}"
        aws cloudformation create-stack \
            --stack-name wga-lambda-${ENV} \
            --template-url https://${S3_BUCKET}.s3.${REGION}.amazonaws.com/cloudformation-template.yaml \
            --parameters file://${PARAMS_FILE} \
            --capabilities CAPABILITY_NAMED_IAM \
            --region ${REGION}
    fi
fi

# 임시 디렉토리 제거
echo -e "${GREEN}임시 디렉토리 정리 중...${NC}"
rm -rf ${TEMP_DIR}

# 스택 생성/업데이트 완료 대기
echo -e "${YELLOW}스택 생성/업데이트 완료 대기 중...${NC}"
if aws cloudformation wait stack-create-complete --stack-name wga-lambda-${ENV} --region ${REGION} 2>/dev/null; then
    echo -e "${GREEN}스택 생성 완료!${NC}"
elif aws cloudformation wait stack-update-complete --stack-name wga-lambda-${ENV} --region ${REGION} 2>/dev/null; then
    echo -e "${GREEN}스택 업데이트 완료!${NC}"
else
    echo -e "${RED}스택 작업 실패 또는 다른 상태입니다. 수동으로 확인해 주세요.${NC}"
    echo -e "${YELLOW}CloudFormation 이벤트 로그를 확인합니다:${NC}"
    aws cloudformation describe-stack-events \
        --stack-name wga-lambda-${ENV} \
        --region ${REGION} \
        --query "StackEvents[?contains(ResourceStatus, 'FAILED')].{Resource:LogicalResourceId, Status:ResourceStatus, Reason:ResourceStatusReason}" \
        --output table
fi

# 배포 완료 후 API 엔드포인트 정보 출력
echo -e "${YELLOW}스택 정보 조회 중...${NC}"
API_ENDPOINT=$(aws cloudformation describe-stacks --stack-name wga-lambda-${ENV} --region ${REGION} --query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue" --output text)

if [ "$API_ENDPOINT" = "None" ] || [ -z "$API_ENDPOINT" ]; then
    echo -e "${YELLOW}API 엔드포인트를 찾을 수 없습니다. 다음 명령으로 모든 출력값을 확인하세요:${NC}"
    echo -e "aws cloudformation describe-stacks --stack-name wga-lambda-${ENV} --region ${REGION} --query \"Stacks[0].Outputs\" --output json"
else
    echo -e "${GREEN}배포 완료!${NC}"
    echo -e "${GREEN}API 엔드포