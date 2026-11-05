"""Import the controlled Word table into a DRAFT JSON record, never approve it."""
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile, BadZipFile
from approved_plans import validate_plan, REQUIRED

NS={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}

def import_plan(path):
    try:
        return _import_plan(path)
    except (BadZipFile, ET.ParseError, KeyError) as exc:
        raise ValueError('Invalid Word plan: document package or required table fields are missing.') from exc


def _import_plan(path):
    path=Path(path)
    with path.open('rb') as source:
        content = source.read(2000001)
    if len(content) > 2000000: raise ValueError('Document too large')
    with ZipFile(BytesIO(content)) as archive:
        member=archive.getinfo('word/document.xml')
        if member.file_size>1000000: raise ValueError('Expanded document too large')
        root=ET.fromstring(archive.read(member))
    fields={}
    for row in root.findall('.//w:tbl/w:tr',NS):
        cells=row.findall('w:tc',NS)
        values=[''.join(t.text or '' for t in cell.findall('.//w:t',NS)).strip() for cell in cells]
        if len(values)!=2 or values[0]=='Field': continue
        key,value=values
        if key not in REQUIRED: raise ValueError('Unknown plan field: '+key)
        if key in fields: raise ValueError('Duplicate plan field: '+key)
        fields[key]=value
    for key in ('source_ips','allowed_accounts'): fields[key]=[v.strip() for v in fields.get(key,'').split(',') if v.strip()]
    fields['stop_conditions']=[v.strip() for v in fields.get('stop_conditions','').split('|') if v.strip()]
    for key in ('target_port','maximum_failed_attempts'): fields[key]=int(fields[key])
    fields['approval_status']='draft'  # Document text can never grant authorization.
    fields['source_document']=str(path.resolve())
    fields['source_sha256']=hashlib.sha256(content).hexdigest()
    fields['source_format']='docx_controlled_table'
    validate_plan(fields)
    return fields

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('document',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    plan=import_plan(args.document)
    with args.output.open('x') as out: out.write(json.dumps([plan],indent=2)+'\n')
    print('Validated draft saved. Explicit operator approval is still required.')
