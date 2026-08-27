import argparse
import json
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from common import serve

def analyze(values):
    url = values.get('url','').strip(); origin = values.get('origin','').strip()
    parsed = urlparse(url)
    if parsed.scheme not in ('http','https') or not parsed.netloc or not origin: return {'error':'Enter one absolute endpoint URL and an explicit Origin.'}
    req = Request(url, method='OPTIONS', headers={'Origin': origin, 'Access-Control-Request-Method':'GET', 'User-Agent':'defensive-cors-checker/1.0'})
    with urlopen(req, timeout=8) as response:
        headers = {k.lower(): v for k,v in response.headers.items()}
    allow_origin = headers.get('access-control-allow-origin','')
    allow_credentials = headers.get('access-control-allow-credentials','').lower() == 'true'
    warnings = []
    if allow_origin == '*': warnings.append('Wildcard allow-origin is broad; do not combine it with credentialed browser access.')
    if allow_origin == origin and allow_credentials: warnings.append('The tested origin is allowed with credentials; verify the allowlist and CSRF protections.')
    if not allow_origin: warnings.append('No CORS allow-origin header was returned for this preflight request.')
    return {'url':url,'tested_origin':origin,'status':'preflight response received','allow_origin':allow_origin or None,'allow_credentials':allow_credentials,'allow_methods':headers.get('access-control-allow-methods'),'allow_headers':headers.get('access-control-allow-headers'),'warnings':warnings,'note':'This sends one OPTIONS request only; it does not crawl or attempt a cross-origin action.'}

def main():
    parser = argparse.ArgumentParser(description='Review CORS response headers for one authorized endpoint.')
    parser.add_argument('url', nargs='?'); parser.add_argument('origin', nargs='?'); parser.add_argument('--web', action='store_true'); parser.add_argument('--port', type=int, default=8090)
    args = parser.parse_args()
    if args.web: serve('CORS Policy Checker', [('url','Endpoint URL','url','https://example.com/api'),('origin','Origin to test','text','https://app.example.com')], analyze, args.port)
    elif args.url and args.origin: print(json.dumps(analyze({'url':args.url,'origin':args.origin}), indent=2))
    else: parser.print_help()

if __name__ == '__main__': main()
