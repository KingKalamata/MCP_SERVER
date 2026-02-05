from gvm.connections import UnixSocketConnection, TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree

from .. import config

class OpenVASScanner:
    def __init__(self, host=None, port=None, user=None, password=None, connection_type='tls'):
        self.host = host or config.GVM_HOST
        self.port = port or config.GVM_PORT
        self.user = user or config.GVM_USER
        self.password = password or config.GVM_PASSWORD
        self.connection_type = connection_type
        self.gmp = None

    def connect(self):
        """Establishes a connection to the GVM."""
        try:
            if self.connection_type == 'tls':
                connection = TLSConnection(hostname=self.host, port=self.port)
            elif self.connection_type == 'unix':
                connection = UnixSocketConnection()
            else:
                raise ValueError("Invalid connection type specified.")

            transform = EtreeCheckCommandTransform()
            self.gmp = Gmp(connection=connection, transform=transform)
            self.gmp.connect()
            self.gmp.authenticate(self.user, self.password)
        except Exception as e:
            raise ConnectionError(f"Failed to connect to GVM: {e}")

    def disconnect(self):
        """Disconnects from the GVM."""
        if self.gmp:
            self.gmp.disconnect()

    def scan(self, target_host):
        """
        Performs a scan on the specified target.
        This is a simplified implementation. A real-world scenario would involve
        more steps like checking scan progress, handling different report formats, etc.
        """
        if not self.gmp:
            self.connect()

        # 1. Create a target
        target_xml = self.gmp.create_target(name=f"Target {target_host}", hosts=[target_host])
        target_id = target_xml.get("id")

        # 2. Get a scan config (e.g., Full and fast)
        scan_configs = self.gmp.get_scan_configs()
        full_and_fast_config = next((sc for sc in scan_configs if "Full and fast" in sc.find("name").text), None)
        if not full_and_fast_config:
            raise Exception("Could not find 'Full and fast' scan configuration.")
        scan_config_id = full_and_fast_config.get("id")
        
        # 3. Create and start a task
        task_xml = self.gmp.create_task(
            name=f"Scan {target_host}",
            config_id=scan_config_id,
            target_id=target_id
        )
        task_id = task_xml.get("id")
        self.gmp.start_task(task_id)

        # In a real application, you would wait for the task to complete.
        # For this example, we'll just return the task ID.
        return {"message": f"Scan started for {target_host}", "task_id": task_id}


def run_openvas_scan(target_host):
    """
    Runs an OpenVAS scan on the given target host.
    """
    try:
        scanner = OpenVASScanner()
        scanner.connect()
        result = scanner.scan(target_host)
        scanner.disconnect()
        return result
    except Exception as e:
        return {"error": str(e)}

if __name__ == '__main__':
    # This is an example and requires a running GVM instance.
    # Replace with a target you are authorized to scan.
    # print(run_openvas_scan('127.0.0.1'))
    pass
