pipeline {
    agent {
        kubernetes {
            yaml """
apiVersion: v1
kind: Pod
metadata:
  labels:
    app: jenkins-agent-maven
spec:
  containers:
  - name: maven
    image: maven:3.9.9-eclipse-temurin-17
    command: ['cat']
    tty: true
    volumeMounts:
    - name: m2-repo
      mountPath: /root/.m2
  - name: oc
    image: quay.io/openshift/origin-cli:latest
    command: ['cat']
    tty: true
  volumes:
  - name: m2-repo
    emptyDir: {}
"""
        }
    }
    environment {
        APP_NAME = "api-gateway"
        BUILD_NAME = "api-gateway"
        DEPLOY_DIR = "deploy/openshift"
    }
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('OpenShift Login') {
            steps {
                container('oc') {
                    withCredentials([string(credentialsId: 'openshift-token', variable: 'OPENSHIFT_TOKEN')]) {
                        sh '''
                          OPENSHIFT_SERVER="${OPENSHIFT_SERVER:-https://api.crc.testing:6443}"
                          OPENSHIFT_PROJECT="${OPENSHIFT_PROJECT:-platform}"
                          oc login --token="$OPENSHIFT_TOKEN" --server="$OPENSHIFT_SERVER" --insecure-skip-tls-verify=true
                          oc project "$OPENSHIFT_PROJECT"
                        '''
                    }
                }
            }
        }
        stage('Build Maven') {
            steps {
                container('maven') {
                    sh 'mvn clean package -DskipTests'
                }
            }
        }
        stage('Build Image') {
            steps {
                container('oc') {
                    script {
                        sh 'oc new-build --name=${BUILD_NAME} --binary --strategy=docker || true'
                        sh 'oc start-build ${BUILD_NAME} --from-dir=. --follow'
                    }
                }
            }
        }
        stage('Deploy') {
            steps {
                container('oc') {
                    sh 'oc apply -f ${DEPLOY_DIR}/'
                    sh 'oc rollout status deployment/${APP_NAME} --timeout=240s'
                }
            }
        }

        stage('Patch Route TLS') {
            steps {
                container('oc') {
                    sh '''
                      OPENSHIFT_PROJECT="${OPENSHIFT_PROJECT:-platform}"
                      ROUTE_NAME="${APP_NAME}"
                      for i in $(seq 1 10); do
                        oc -n "$OPENSHIFT_PROJECT" get route "$ROUTE_NAME" >/dev/null 2>&1 && break
                        sleep 3
                      done
                      CA=$(oc -n openshift-config-managed get configmap openshift-service-ca.crt -o jsonpath='{.data.service-ca\.crt}')
                      CA_ESCAPED=$(printf '%s' "$CA" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g')
                      oc -n "$OPENSHIFT_PROJECT" patch route "$ROUTE_NAME" --type=merge -p "{\"spec\":{\"tls\":{\"destinationCACertificate\":\"$CA_ESCAPED\"}}}"
                    '''
                }
            }
        }
    }
}
