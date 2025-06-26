from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPropertyType, OAAPermission
import os, sys
import requests
from dotenv import load_dotenv
load_dotenv()

veza_url = os.getenv('VEZA_URL')
veza_api_key = os.getenv('VEZA_API_KEY')
headers = {
    'Accept': 'application/json',
    'Authorization': f'Token token={os.getenv("PAGERDUTY_API_KEY")}'
}

def main():
    app = CustomApplication(name='Sample App', application_type='PagerDuty')

    # Define Custom Properties
    app.property_definitions.define_local_user_property('email', OAAPropertyType.STRING)
    app.property_definitions.define_local_user_property('is_billed', OAAPropertyType.BOOLEAN)
    app.property_definitions.define_resource_property('team', 'pagerduty_id', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('team', 'summary', OAAPropertyType.STRING)
    app.property_definitions.define_resource_property('team', 'default_role', OAAPropertyType.STRING)

    # Add Application specific permissions
    app.add_custom_permission('admin', permissions=[OAAPermission.DataWrite, OAAPermission.DataRead, OAAPermission.DataDelete, OAAPermission.MetadataRead, OAAPermission.MetadataWrite])
    app.add_custom_permission('limited_user', permissions=[OAAPermission.DataRead, OAAPermission.MetadataRead])
    app.add_custom_permission('manager', permissions=[OAAPermission.DataWrite, OAAPermission.DataRead, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    app.add_custom_permission('observer', permissions=[OAAPermission.DataRead, OAAPermission.MetadataRead])
    app.add_custom_permission('owner', permissions=[OAAPermission.DataWrite, OAAPermission.DataRead, OAAPermission.DataDelete, OAAPermission.MetadataRead, OAAPermission.MetadataWrite])
    app.add_custom_permission('read_only_limited_user', permissions=[OAAPermission.MetadataRead])
    app.add_custom_permission('read_only_user', permissions=[OAAPermission.DataRead, OAAPermission.MetadataRead])
    app.add_custom_permission('responder', permissions=[OAAPermission.DataWrite, OAAPermission.DataRead])
    app.add_custom_permission('restricted_access', permissions=[OAAPermission.MetadataRead, OAAPermission.MetadataWrite])
    app.add_custom_permission('user', permissions=[OAAPermission.DataRead, OAAPermission.MetadataRead])

    # Add Local Roles
    app.add_local_role('Global Admin', unique_id='admin', permissions=['admin'])
    app.add_local_role('Responder', unique_id='limited_user', permissions=['limited_user'])
    app.add_local_role('Observer', unique_id='observer', permissions=['observer'])
    app.add_local_role('Account Owner', unique_id='owner', permissions=['owner'])
    app.add_local_role('Limited Stakeholder', unique_id='read_only_limited_user', permissions=['read_only_limited_user'])
    app.add_local_role('Full Stakeholder', unique_id='read_only_user', permissions=['read_only_user'])
    app.add_local_role('Restricted Access', unique_id='restricted_access', permissions=['restricted_access'])
    app.add_local_role('User', unique_id='user', permissions=['user'])
    app.add_local_role('Manager', unique_id='manager', permissions=['manager'])

    # Add Local Users
    response = requests.get('https://api.pagerduty.com/users?limit=100', headers=headers)
    response = response.json()
    for user in response['users']:
        # Add local user. Link the local user to an IdP using email
        new_user = app.add_local_user(user.get('name'), 
                                      unique_id=user.get('id'), 
                                      identities=[user.get('email')])
        # Associate user to role
        new_user.add_role(user.get('role'), apply_to_application=True)
        # Populate custom properties
        new_user.set_property('email', user.get('email'))
        new_user.set_property('is_billed', user.get('billed'))

    # Add Local Groups
    response = requests.get('https://api.pagerduty.com/teams?limit=100', headers=headers)
    teams = response.json()['teams']
    for team in teams:
        app.add_local_group(team.get('name'), unique_id=team.get("id"))

    # Add Resources (Map PagerDuty Teams to Veza Custom Application Teamplate Resources)
    for team in teams:        
        # Add local resource
        resource = app.add_resource(team.get('name'), resource_type='team')
        # Populate built-in property description (max 1,024 char)
        resource.description = team.get('description')[:255] if team.get('description') else None
        # Populate Custom Properties
        resource.set_property('pagerduty_id', team.get('id'))
        resource.set_property('summary', team.get('summary'))
        resource.set_property('default_role', team.get('default_role'))

    # Assign local roles to users
    for team in app.resources:
        resource = app.resources[team]
        team_id = resource.properties.get('pagerduty_id')
        response = requests.get(f'https://api.pagerduty.com/teams/{team_id}/members',
                                headers=headers)
        response = response.json()
        for member in response['members']:
            app.local_users[member['user']['id']].add_role(member['role'], resources=[resource])

            # Add local user to group
            app.local_users[member['user']['id']].add_group(team_id)


    # Print the payload for debugging
    # print(json.dumps(app.get_payload()))

    # Connect to the API to Push to Veza
    provider_name = 'Lab-PagerDuty'
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