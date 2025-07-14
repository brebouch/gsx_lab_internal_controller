import paramiko

def get_dcloud_session_xml():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname="198.18.133.36", username="admin", password="C1sco12345", port=22)
    sftp_client=ssh.open_sftp()

    sftp_client.put("C:\\dcloud\\session.xml", './session.xml')
    sftp_client.close()
    ssh.close()
