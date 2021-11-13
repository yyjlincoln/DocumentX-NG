from os import supports_bytes_environ


class DuplicateKeyError(Exception):
    def __init__(self, key: str, line: int=0):
        self.key = key
        self.msg = "Duplicate key: " + key + \
            ' at line ' + (str(line) if line else 'Unknown')
        super().__init__(self.msg)


class InvalidKeyValuePairError(Exception):
    def __init__(self, content: str, line: int=0):
        self.content = content
        self.msg = "Invalid key-value pair of content: " + \
            content + ' at line ' + (str(line) if line else 'Unknown')
        super().__init__(self.msg)


class UnknownSeparatorError(Exception):
    def __init__(self, line: int=0):
        self.msg = "Required key-value pair separator was not present in the header " + ' at line ' + (str(line) if line else 'Unknown')
        super().__init__(self.msg)


class Backup():
    def __init__(self, content: str) -> None:
        self.content: str = content
        self.headers: dict[str, str] = {}
        self.separator = None
        self.data = []

        # Detects header
        cont: list[str] = content.split('\n\n', 1)

        if len(cont) == 1:
            cont.append('')  # Empty backup

        headers, backup = cont
        headers = headers.split('\n')

        for lineNumber in range(len(headers)):
            line = headers[lineNumber]
            record = line.split('=', 1)
            if len(record) == 1:
                raise InvalidKeyValuePairError(
                    content=line, line=lineNumber + 1)
            key, value = record
            if key in self.headers:
                raise DuplicateKeyError(key)
            self.headers[key] = value

        if 'separator' not in self.headers:
            raise UnknownSeparatorError(line=lineNumber + 1) # Which will show the end of the header
        
        self.separator = self.headers['separator']

        # Now reads the data
        self.data = [entry for entry in backup.split('\n=='+self.separator+'==\n') if entry]