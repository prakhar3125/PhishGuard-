import hashlib
import magic
import olefile
import zipfile
import re
from typing import Dict, List, Optional

class AttachmentAnalyzer:
    def __init__(self):
        self.dangerous_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.vbs', '.js', 
            '.jar', '.scr', '.com', '.pif', '.hta'
        ]
        
        self.suspicious_office_extensions = [
            '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm'
        ]
        
        self.malicious_vba_keywords = [
            b'AutoOpen', b'Document_Open', b'Workbook_Open',
            b'Auto_Open', b'AutoExec', b'AutoClose',
            b'ShellExecute', b'Shell', b'CreateObject',
            b'WScript.Shell', b'powershell', b'cmd.exe',
            b'URLDownloadToFile', b'ADODB.Stream',
            b'GetObject', b'CallByName'
        ]

    def analyze_attachment(self, filename: str, content: bytes) -> Dict:
        """Comprehensive attachment analysis"""
        findings = {
            'filename': filename,
            'size': len(content),
            'sha256': hashlib.sha256(content).hexdigest(),
            'md5': hashlib.md5(content).hexdigest(),
            'file_type': self._identify_file_type(content),
            'is_suspicious': False,
            'risk_score': 0,
            'findings': []
        }
        
        # Check file extension
        extension_risk = self._check_extension(filename)
        findings['risk_score'] += extension_risk['score']
        findings['findings'].extend(extension_risk['findings'])
        
        # Check file type mismatch
        if self._check_file_type_mismatch(filename, findings['file_type']):
            findings['risk_score'] += 30
            findings['findings'].append('File extension does not match actual file type')
        
        # Analyze Office documents
        if self._is_office_document(filename, content):
            office_analysis = self._analyze_office_document(content)
            findings['risk_score'] += office_analysis['risk_score']
            findings['findings'].extend(office_analysis['findings'])
            findings['has_macros'] = office_analysis.get('has_macros', False)
            findings['macro_analysis'] = office_analysis.get('macro_details', {})
        
        # Analyze PDFs
        elif filename.lower().endswith('.pdf'):
            pdf_analysis = self._analyze_pdf(content)
            findings['risk_score'] += pdf_analysis['risk_score']
            findings['findings'].extend(pdf_analysis['findings'])
        
        # Analyze archives
        elif self._is_archive(filename):
            archive_analysis = self._analyze_archive(content)
            findings['risk_score'] += archive_analysis['risk_score']
            findings['findings'].extend(archive_analysis['findings'])
        
        # Check for embedded URLs
        url_check = self._check_embedded_urls(content)
        findings['risk_score'] += url_check['risk_score']
        findings['findings'].extend(url_check['findings'])
        
        # Set overall verdict
        findings['is_suspicious'] = findings['risk_score'] >= 40
        
        return findings

    def _identify_file_type(self, content: bytes) -> str:
        """Identify file type using magic bytes"""
        try:
            mime = magic.Magic(mime=True)
            return mime.from_buffer(content)
        except:
            return "unknown"

    def _check_extension(self, filename: str) -> Dict:
        """Check for dangerous file extensions"""
        findings = []
        score = 0
        
        if any(filename.lower().endswith(ext) for ext in self.dangerous_extensions):
            score = 100
            findings.append(f'Dangerous file extension: {filename}')
        
        elif any(filename.lower().endswith(ext) for ext in self.suspicious_office_extensions):
            score = 50
            findings.append(f'Macro-enabled Office document: {filename}')
        
        # Check for double extensions
        if filename.count('.') > 1:
            score += 20
            findings.append('File has multiple extensions (possible obfuscation)')
        
        return {'score': score, 'findings': findings}

    def _check_file_type_mismatch(self, filename: str, detected_type: str) -> bool:
        """Check if file extension matches actual file type"""
        extension_to_mime = {
            '.pdf': 'application/pdf',
            '.docx': 'application/vnd.openxmlformats',
            '.xlsx': 'application/vnd.openxmlformats',
            '.zip': 'application/zip',
            '.txt': 'text/plain'
        }
        
        for ext, mime in extension_to_mime.items():
            if filename.lower().endswith(ext):
                return mime not in detected_type
        
        return False

    def _is_office_document(self, filename: str, content: bytes) -> bool:
        """Check if file is an Office document"""
        office_extensions = ['.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm']
        return any(filename.lower().endswith(ext) for ext in office_extensions)

    def _analyze_office_document(self, content: bytes) -> Dict:
        """Analyze Office documents for macros and suspicious content"""
        findings = []
        risk_score = 0
        has_macros = False
        macro_details = {}
        
        try:
            # Check if it's an OLE file (old Office format)
            if olefile.isOleFile(content):
                ole = olefile.OleFileIO(content)
                
                # Check for VBA macros
                if ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR'):
                    has_macros = True
                    risk_score += 40
                    findings.append('Document contains VBA macros')
                    
                    # Extract and analyze VBA code
                    macro_analysis = self._analyze_vba_macros(ole)
                    risk_score += macro_analysis['risk_score']
                    findings.extend(macro_analysis['findings'])
                    macro_details = macro_analysis['details']
                
                ole.close()
            
            # Check for new Office format (ZIP-based)
            elif self._is_ooxml_format(content):
                ooxml_analysis = self._analyze_ooxml(content)
                has_macros = ooxml_analysis['has_macros']
                risk_score += ooxml_analysis['risk_score']
                findings.extend(ooxml_analysis['findings'])
        
        except Exception as e:
            findings.append(f'Error analyzing Office document: {str(e)}')
        
        return {
            'risk_score': risk_score,
            'findings': findings,
            'has_macros': has_macros,
            'macro_details': macro_details
        }

    def _analyze_vba_macros(self, ole: olefile.OleFileIO) -> Dict:
        """Analyze VBA macro code for malicious patterns"""
        findings = []
        risk_score = 0
        details = {'suspicious_calls': [], 'auto_execute': False}
        
        try:
            # Extract VBA streams
            for stream in ole.listdir():
                stream_name = '/'.join(stream)
                
                if 'VBA' in stream_name or 'Macros' in stream_name:
                    try:
                        vba_code = ole.openstream(stream).read()
                        
                        # Check for auto-execute functions
                        for keyword in [b'AutoOpen', b'Document_Open', b'Workbook_Open', b'Auto_Open']:
                            if keyword in vba_code:
                                risk_score += 50
                                findings.append(f'Auto-execute macro detected: {keyword.decode()}')
                                details['auto_execute'] = True
                        
                        # Check for suspicious API calls
                        for keyword in self.malicious_vba_keywords:
                            if keyword in vba_code:
                                risk_score += 30
                                suspicious_call = keyword.decode('utf-8', errors='ignore')
                                findings.append(f'Suspicious VBA call: {suspicious_call}')
                                details['suspicious_calls'].append(suspicious_call)
                        
                        # Check for obfuscation
                        if self._detect_vba_obfuscation(vba_code):
                            risk_score += 20
                            findings.append('Possible VBA code obfuscation detected')
                    
                    except:
                        pass
        
        except Exception as e:
            findings.append(f'Error analyzing VBA: {str(e)}')
        
        return {
            'risk_score': min(risk_score, 100),
            'findings': findings,
            'details': details
        }

    def _detect_vba_obfuscation(self, vba_code: bytes) -> bool:
        """Detect common VBA obfuscation techniques"""
        # Check for excessive Chr() calls (common obfuscation)
        chr_count = vba_code.count(b'Chr(')
        if chr_count > 10:
            return True
        
        # Check for base64-like strings
        if re.search(rb'[A-Za-z0-9+/]{50,}={0,2}', vba_code):
            return True
        
        return False

    def _is_ooxml_format(self, content: bytes) -> bool:
        """Check if content is OOXML format (ZIP-based)"""
        return content[:4] == b'PK\x03\x04'

    def _analyze_ooxml(self, content: bytes) -> Dict:
        """Analyze OOXML documents"""
        findings = []
        risk_score = 0
        has_macros = False
        
        try:
            import io
            zip_file = zipfile.ZipFile(io.BytesIO(content))
            
            # Check for VBA project
            if 'word/vbaProject.bin' in zip_file.namelist() or \
               'xl/vbaProject.bin' in zip_file.namelist() or \
               'ppt/vbaProject.bin' in zip_file.namelist():
                has_macros = True
                risk_score += 40
                findings.append('Document contains VBA macros')
            
            # Check for external relationships (can be used for data exfiltration)
            for name in zip_file.namelist():
                if 'rels' in name:
                    rels_content = zip_file.read(name)
                    if b'TargetMode="External"' in rels_content:
                        risk_score += 20
                        findings.append('Document contains external relationships')
            
            zip_file.close()
        
        except Exception as e:
            findings.append(f'Error analyzing OOXML: {str(e)}')
        
        return {
            'risk_score': risk_score,
            'findings': findings,
            'has_macros': has_macros
        }

    def _analyze_pdf(self, content: bytes) -> Dict:
        """Analyze PDF files for suspicious content"""
        findings = []
        risk_score = 0
        
        # Check for JavaScript
        if b'/JavaScript' in content or b'/JS' in content:
            risk_score += 50
            findings.append('PDF contains JavaScript')
        
        # Check for embedded files
        if b'/EmbeddedFile' in content:
            risk_score += 30
            findings.append('PDF contains embedded files')
        
        # Check for auto-actions
        if b'/OpenAction' in content or b'/AA' in content:
            risk_score += 40
            findings.append('PDF contains auto-execute actions')
        
        # Check for external links
        if b'/URI' in content:
            risk_score += 10
            findings.append('PDF contains external URLs')
        
        return {'risk_score': risk_score, 'findings': findings}

    def _is_archive(self, filename: str) -> bool:
        """Check if file is an archive"""
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz']
        return any(filename.lower().endswith(ext) for ext in archive_extensions)

    def _analyze_archive(self, content: bytes) -> Dict:
        """Analyze archive files"""
        findings = []
        risk_score = 0
        
        try:
            import io
            zip_file = zipfile.ZipFile(io.BytesIO(content))
            
            # Check for password protection
            for file_info in zip_file.filelist:
                if file_info.flag_bits & 0x1:  # Encrypted
                    risk_score += 50
                    findings.append('Archive is password-protected')
                    break
            
            # Check for dangerous files inside
            for filename in zip_file.namelist():
                if any(filename.lower().endswith(ext) for ext in self.dangerous_extensions):
                    risk_score += 70
                    findings.append(f'Archive contains dangerous file: {filename}')
            
            zip_file.close()
        
        except zipfile.BadZipFile:
            findings.append('Invalid or corrupted archive')
        except Exception as e:
            findings.append(f'Error analyzing archive: {str(e)}')
        
        return {'risk_score': risk_score, 'findings': findings}

    def _check_embedded_urls(self, content: bytes) -> Dict:
        """Check for embedded URLs in file content"""
        findings = []
        risk_score = 0
        
        try:
            # Look for URLs in the content
            text = content.decode('utf-8', errors='ignore')
            url_pattern = re.compile(r'https?://[^\s]+')
            urls = url_pattern.findall(text)
            
            if urls:
                risk_score += 10
                findings.append(f'File contains {len(urls)} embedded URL(s)')
        
        except:
            pass
        
        return {'risk_score': risk_score, 'findings': findings}
