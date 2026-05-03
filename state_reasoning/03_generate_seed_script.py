import sys
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_READ_DATA, FILE_Read_Data

# ==========================================
# 사용자 설정 (환경에 맞게 변경하세요)
# ==========================================
TARGET_IP = '192.168.1.10'
USERNAME = 'user'
PASSWORD = 'password'
SHARE_NAME = 'share'      # 접속할 공유 폴더명
TEST_FILENAME = 'seed_test.txt' # 생성할 파일명
# ==========================================

def generate_seed_traffic():
    print(f"[*] Starting SMB2 Traffic Generation for Seed...")
    
    try:
        # Step 1 & 2: SMB2_NEGOTIATE & SMB2_SESSION_SETUP
        # Impacket이 자동으로 가장 최신 프로토콜(SMB 3.1.1 등)로 협상하고 인증합니다.
        # JSON Rationale: "Establishes connection... Authenticates user..."
        smb_client = SMBConnection(TARGET_IP, TARGET_IP, sess_port=445)
        smb_client.login(USERNAME, PASSWORD)
        print("[+] Step 1 & 2: Negotiate & Session Setup - Success")

        # Step 3: SMB2_TREE_CONNECT
        # JSON Rationale: "Connects to a specific share..."
        tid = smb_client.connectTree(SHARE_NAME)
        print(f"[+] Step 3: Tree Connect - Success (TreeID: {tid})")

        # Step 4: SMB2_CREATE
        # JSON Rationale: "Opens a file to obtain a file handle..."
        # 파일을 실제로 생성하거나 엽니다. (Generic Read/Write 권한)
        fid = smb_client.createFile(tid, TEST_FILENAME)
        print(f"[+] Step 4: Create (File Open) - Success (FileID: {fid})")

        # Step 5: SMB2_QUERY_INFO
        # JSON Rationale: "Queries file information... triggers Smb2ValidateVolumeObjectsMatch"
        # 
        # [중요] Seed의 품질을 높이기 위한 전략:
        # 일반적인 파일 정보(FileBasicInformation)를 요청합니다.
        # Fuzzer는 이 패킷의 'InfoType'이나 'FileInfoClass' 필드를 변조하여
        # 'Volume' 관련 클래스로 변경하면서 취약점을 건드리게 될 것입니다.
        try:
            # queryInfo(tid, fid, infoType, fileInfoClass)
            # infoType=1 (File), fileInfoClass=5 (FileStandardInformation - 가장 무난한 값)
            info = smb_client.queryInfo(tid, fid, infoType=1, fileInfoClass=5)
            print("[+] Step 5: Query Info - Success")
        except Exception as e:
            # 쿼리가 실패해도 패킷은 전송되었으므로 Seed로는 유효할 수 있음
            print(f"[-] Step 5: Query Info - Sent but returned error (Expected in some cases): {e}")

        # Cleanup (Fuzzer에는 포함되지 않겠지만 깔끔한 종료를 위해)
        smb_client.closeFile(tid, fid)
        smb_client.disconnectTree(tid)
        smb_client.logoff()
        print("[*] Traffic generation complete.")

    except Exception as e:
        print(f"[!] Critical Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    generate_seed_traffic()