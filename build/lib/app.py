__version__ = "0.3.0"
import argparse
import json
from urllib.error import HTTPError
from urllib.request import Request
from common import serve
from security_utils import bounded_read, open_no_redirect, valid_origin, validate_url

def analyze(values):
    try: url=validate_url(values.get('url',''), resolve=True); origin=valid_origin(values.get('origin',''))
    except ValueError as exc: return {'error':str(exc)}
    req=Request(url.geturl(),method='OPTIONS',headers={'Origin':origin,'Access-Control-Request-Method':'GET','User-Agent':'defensive-cors-checker/2.0'})
    try:
        with open_no_redirect(req,timeout=8) as response: headers={k.lower():v[:2048] for k,v in response.headers.items()}; status=response.status
    except HTTPError as exc:
        headers={k.lower():v[:2048] for k,v in exc.headers.items()}; status=exc.code
    except Exception as exc: return {'error':f'CORS request failed: {type(exc).__name__}'}
    allow_origin=headers.get('access-control-allow-origin',''); allow_credentials=headers.get('access-control-allow-credentials','').lower()=='true'; warnings=[]
    if allow_origin=='*': warnings.append('Wildcard allow-origin is broad; do not combine with credentialed browser access.')
    if allow_origin==origin and allow_credentials: warnings.append('The tested origin is allowed with credentials; verify the allowlist and CSRF protections.')
    if not allow_origin: warnings.append('No CORS allow-origin header was returned for this preflight request.')
    return {'url':url.geturl(),'tested_origin':origin,'status':status,'allow_origin':allow_origin or None,'allow_credentials':allow_credentials,'allow_methods':headers.get('access-control-allow-methods'),'allow_headers':headers.get('access-control-allow-headers'),'warnings':warnings,'redirects_followed':False,'note':'One OPTIONS request only; no cross-origin action is attempted.'}
def main():
    parser=argparse.ArgumentParser(description='Review CORS response headers for one authorized endpoint.')
    parser.add_argument('url',nargs='?'); parser.add_argument('origin',nargs='?'); parser.add_argument('--web',action='store_true'); parser.add_argument('--port',type=int,default=8090)
    parser.add_argument('--version',action='version',version=__version__)
    args=parser.parse_args()
    if args.web: serve('CORS Policy Checker',[('url','Endpoint URL','url','https://example.com/api'),('origin','Origin to test','text','https://app.example.com')],analyze,args.port)
    elif args.url and args.origin: print(json.dumps(analyze({'url':args.url,'origin':args.origin}),indent=2))
    else: parser.print_help()
if __name__=='__main__': main()
