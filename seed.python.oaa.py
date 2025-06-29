from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPropertyType, OAAPermission
import os, sys
import requests
 
veza_url = os.getenv('VEZA_URL')
veza_api_key = os.getenv('VEZA_API_KEY')
 
def main():
    app = CustomApplication(name='Sample App', application_type='PagerDuty')
 
    # Define Custom Properties
 
    # Add Application specific permissions
 
    # Add Local Roles
 
    # Add Local Users
     
    # Add Local Groups
         
    # Add Resources (Map PagerDuty Teams to Veza Custom Application Teamplate Resources)
 
    # Assign local roles to users
 
    # Connect to the API to Push to Veza
    provider_name = 'Sample-PagerDuty'
    veza_con = OAAClient(url=veza_url, api_key=veza_api_key)
    provider = veza_con.get_provider(provider_name)
    if not provider:
        provider = veza_con.create_provider(provider_name, 'application')
    try:
        response = veza_con.push_application(provider_name,
                                             data_source_name=f'{app.name} ({app.application_type})',
                                             application_object=app,
                                             save_json=False
                                             )
        if response.get('warnings', None):
            # Veza may return warnings on a successful uploads. These are informational warnings that did not stop the processing
            # of the OAA data but may be important. Specifically identities that cannot be resolved will be returned here.
            print('-- Push succeeded with warnings:')
            for e in response['warnings']:
                print(f'  - {e}')
    except OAAClientError as e:
        print(f'-- Error: {e.error}: {e.message} ({e.status_code})', file=sys.stderr)
        if hasattr(e, 'details'):
            for d in e.details:
                print(f'  -- {d}', file=sys.stderr)
    return
 
if __name__ == '__main__':
    main()