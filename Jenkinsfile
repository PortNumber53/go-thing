pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                git branch: 'master', url: 'YOUR_GIT_REPOSITORY_URL' // Replace with your repository URL and branch
            }
        }

        stage('Build') {
            steps {
                script {
                    // Build agent
                    sh 'go build -o agent agent.go'
                    // Build toolserver
                    sh 'go build -o toolserver tools/toolserver.go'
                }
            }
        }

        stage('Deploy to zero2wa') {
            steps {
                script {
                    def remoteHost = 'zero2wa'
                    def deployDir = '/opt/go-thing' // Target directory on remote host

                    // Ensure deploy directory exists
                    sshagent(credentials: ['your-ssh-credential-id']) { // Replace with your Jenkins SSH credential ID
                        sh "ssh -o StrictHostKeyChecking=no ${remoteHost} 'mkdir -p ${deployDir}'"
                    }

                    // Copy binaries
                    sshagent(credentials: ['your-ssh-credential-id']) { // Replace with your Jenkins SSH credential ID
                        sh "scp -o StrictHostKeyChecking=no agent ${remoteHost}:${deployDir}/agent"
                        sh "scp -o StrictHostKeyChecking=no toolserver ${remoteHost}:${deployDir}/toolserver"
                        sh "scp -o StrictHostKeyChecking=no start.sh ${remoteHost}:${deployDir}/start.sh"
                        sh "scp -o StrictHostKeyChecking=no config.ini.sample ${remoteHost}:${deployDir}/config.ini.sample"
                    }

                    // Restart application (basic example, consider systemd or similar for production)
                    sshagent(credentials: ['your-ssh-credential-id']) { // Replace with your Jenkins SSH credential ID
                        sh "ssh -o StrictHostKeyChecking=no ${remoteHost} 'pkill -f agent || true; pkill -f toolserver || true; nohup ${deployDir}/start.sh > /dev/null 2>&1 &'"
                    }
                }
            }
        }

        stage('Deploy to zero2wb') {
            steps {
                script {
                    def remoteHost = 'zero2wb'
                    def deployDir = '/opt/go-thing' // Target directory on remote host

                    // Ensure deploy directory exists
                    sshagent(credentials: ['your-ssh-credential-id']) { // Replace with your Jenkins SSH credential ID
                        sh "ssh -o StrictHostKeyChecking=no ${remoteHost} 'mkdir -p ${deployDir}'"
                    }

                    // Copy binaries
                    sshagent(credentials: ['your-ssh-credential-id']) { // Replace with your Jenkins SSH credential ID
                        sh "scp -o StrictHostKeyChecking=no agent ${remoteHost}:${deployDir}/agent"
                        sh "scp -o StrictHostKeyChecking=no toolserver ${remoteHost}:${deployDir}/toolserver"
                        sh "scp -o StrictHostKeyChecking=no start.sh ${remoteHost}:${deployDir}/start.sh"
                        sh "scp -o StrictHostKeyChecking=no config.ini.sample ${remoteHost}:${deployDir}/config.ini.sample"
                    }

                    // Restart application (basic example, consider systemd or similar for production)
                    sshagent(credentials: ['your-ssh-credential-id']) { // Replace with your Jenkins SSH credential ID
                        sh "ssh -o StrictHostKeyChecking=no ${remoteHost} 'pkill -f agent || true; pkill -f toolserver || true; nohup ${deployDir}/start.sh > /dev/null 2>&1 &'"
                    }
                }
            }
        }
    }

    post {
        always {
            cleanWs() // Clean up workspace
        }
        success {
            echo 'Deployment successful!'
        }
        failure {
            echo 'Deployment failed!'
        }
    }
}