# PagerDuty to Veza Integration Guide
## Complete Training, Tips, and FAQ

---

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Code Walkthrough](#code-walkthrough)
4. [Setup Instructions](#setup-instructions)
5. [Authentication Explained](#authentication-explained)
6. [Common Questions & Answers](#common-questions--answers)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)
9. [Customization Guide](#customization-guide)

---

## Overview

### What This Script Does
This Python script acts as a data bridge between **PagerDuty** (incident management platform) and **Veza** (authorization governance platform). It extracts user, team, and permission data from PagerDuty and transforms it into Veza's authorization model for centralized access visibility.

### The Authorization Challenge
As explained in [Veza's official OAA guide](https://veza.com/blog/intelligent-access-for-custom-apps-getting-started-with-vezas-open-authorization-api/), traditional identity systems often stop providing access information at the role level, leaving you to fetch fine-grained authorization data separately from each native system. This creates gaps in visibility and new surfaces for identity-based cyber threats.

### Veza's Solution: The Access Graph
Veza creates a comprehensive **Access Graph** that answers the fundamental question: _"Who can take what action on what data?"_ This graph connects:
- **Identity sources** (IdPs like AD and Okta, HRIS systems like Workday)
- **Data platforms** (Snowflake, databases, file systems)
- **SaaS applications** (like PagerDuty)
- **On-premises applications**

### Why Use This Integration
- **Security Compliance**: Understand all access permissions across systems
- **Access Reviews**: Regular auditing of who has what permissions
- **Risk Management**: Identify over-privileged users or access patterns
- **Centralized Visibility**: See PagerDuty permissions alongside other systems
- **Real-time Analysis**: Answer access questions instantly across all connected systems

### Data Flow
```
PagerDuty API → Python Script → Veza Access Graph → Authorization Insights
```

---

## Prerequisites

### System Requirements
- **Operating System**: macOS, Linux, or Windows
- **Python Version**: Python 3.6 or higher (Python 3.9+ recommended)
- **Network Access**: Internet connectivity to reach PagerDuty and Veza APIs
- **Terminal/Command Line**: Basic familiarity with command line operations

### Required Accounts and Access
- **PagerDuty Account**: Admin access to create API keys
- **Veza Instance**: Access to a Veza deployment with API key creation permissions
- **Development Environment**: Text editor or IDE (VS Code, PyCharm, etc.)

### Python Environment Setup
**Check Your Python Installation:**
```bash
# Check if Python 3 is installed
python3 --version

# Should return something like: Python 3.9.6
```

**If Python is not installed:**
- **macOS**: Install via Homebrew: `brew install python3` or download from python.org
- **Linux**: Use your package manager: `sudo apt install python3 python3-pip` (Ubuntu/Debian)
- **Windows**: Download from python.org and ensure "Add to PATH" is checked

### Required Knowledge
- **Basic Python**: Understanding of variables, functions, and imports
- **Command Line**: How to navigate directories and run commands
- **API Concepts**: Basic understanding of REST APIs and authentication
- **Environment Variables**: How to set and use environment variables

### Before You Start
1. **Verify Python Installation**: Run `python3 --version`
2. **Have API Access Ready**: Ensure you can create API keys in both PagerDuty and Veza
3. **Choose Your Workspace**: Create a dedicated directory for this project
4. **Text Editor Ready**: Have your preferred code editor installed

### Common Setup Issues and Solutions

**"python3: command not found"**
- Install Python 3 from python.org
- On some systems, try `python` instead of `python3`
- Add Python to your PATH environment variable

**"Permission denied" errors**
- Use `python3` instead of `./python.oaa.py` to run the script
- Don't try to execute Python files directly unless you add a shebang line

**Virtual Environment Recommended**
- Always use a virtual environment for Python projects
- Keeps dependencies isolated and prevents conflicts
- Commands: `python3 -m venv venv` then `source venv/bin/activate`

---

## Understanding Veza's Authorization Model

### The Custom Application Template
Before diving into the code, it's important to understand how Veza models authorization. According to [Veza's official OAA documentation](https://veza.com/blog/intelligent-access-for-custom-apps-getting-started-with-vezas-open-authorization-api/), the Custom Application Template is structured as a graph with these key characteristics:

#### Graph Structure
- **Nodes**: Represent entity types (Local Users, Local Groups, Local Roles, Permissions, Resources)
- **Edges**: Represent associations between nodes
- **Flow**: Read left-to-right from users to the resources they can access

#### Key Principles
1. **Optional Entities**: Everything between users and resources is optional
   - You can have Local Groups, Local Roles, both, or neither
   - Users can have direct permissions or inherit through groups/roles

2. **Flexible Relationships**: 
   - Users can be directly granted permissions
   - Users can belong to groups/roles that have permissions
   - Any combination of the above is possible

3. **Normalized Permissions**: All application-specific permissions map to Veza's standard "Effective Permissions" (CRUDMNU model)

### PagerDuty Modeling Approach
For PagerDuty specifically, [Veza's guide](https://veza.com/blog/intelligent-access-for-custom-apps-getting-started-with-vezas-open-authorization-api/) explains the mapping:
- **Local Users**: PagerDuty users
- **Local Groups**: PagerDuty teams (collections of users)
- **Local Roles**: PagerDuty roles (admin, user, observer, etc.)
- **Resources**: PagerDuty teams (things users can have permissions on)
- **Permissions**: Mapped to Veza's effective permissions

**Key Insight**: PagerDuty teams serve a dual purpose - they're both groups (collections of users) AND resources (things users can access).

---

## Code Walkthrough

This section provides a detailed, line-by-line explanation of how the PagerDuty-to-Veza integration works. Each step builds upon the previous one, creating a complete data pipeline.

### 1. Imports and Dependencies - Setting Up Our Toolkit

```python
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPropertyType, OAAPermission
import os, sys
import requests
from dotenv import load_dotenv
```

**What's Happening Here:**
This section imports all the tools our script needs to function. Think of it like gathering all your tools before starting a project.

**Detailed Breakdown:**

**Veza-Specific Imports:**
- `OAAClient`: The main communication channel to Veza's API. Like a telephone that lets us talk to Veza.
- `OAAClientError`: Handles errors when something goes wrong with Veza communication. Like a "call failed" message.
- `CustomApplication`: A template for defining how PagerDuty should look in Veza's system.
- `OAAPropertyType`: Defines what kind of data we're storing (text, numbers, true/false, etc.).
- `OAAPermission`: Pre-defined permission types that Veza understands.

**Standard Python Imports:**
- `os`: Lets us read environment variables (like API keys stored securely).
- `sys`: Provides system-specific functions, used here for error output.
- `requests`: The HTTP library that makes web API calls to PagerDuty.

**Third-Party Import:**
- `dotenv`: Loads our secret configuration from a `.env` file safely.

**Teaching Point:** Always import only what you need. This keeps your code clean and makes dependencies clear.

### 2. Configuration Setup - Loading Our Secrets and Settings

```python
load_dotenv()
veza_url = os.getenv('VEZA_URL')
veza_api_key = os.getenv('VEZA_API_KEY')
headers = {
    'Accept': 'application/json',
    'Authorization': f'Token token={os.getenv("PAGERDUTY_API_KEY")}'
}
```

**What's Happening Here:**
This section loads our configuration and prepares authentication credentials. It's like getting your ID cards ready before entering secure buildings.

**Step-by-Step Explanation:**

1. **`load_dotenv()`**: Reads the `.env` file and makes those variables available to our script
   - **Why**: Keeps secrets out of source code
   - **Security**: Prevents accidentally committing API keys to version control

2. **Environment Variable Loading**:
   ```python
   veza_url = os.getenv('VEZA_URL')          # Where is your Veza instance?
   veza_api_key = os.getenv('VEZA_API_KEY')  # Your Veza access key
   ```
   - **`os.getenv()`**: Safely retrieves environment variables
   - **Returns `None`**: If the variable doesn't exist (good for error checking)

3. **HTTP Headers Setup**:
   ```python
   headers = {
       'Accept': 'application/json',                                    # "I want JSON responses"
       'Authorization': f'Token token={os.getenv("PAGERDUTY_API_KEY")}' # "Here's my PagerDuty ID"
   }
   ```

**Teaching Points:**
- **f-strings**: `f'Token token={variable}'` is Python's modern string formatting
- **Header Purpose**: HTTP headers carry metadata about requests
- **Authentication**: Different APIs use different auth formats (PagerDuty uses "Token token=...")

**Common Mistake:** Using single quotes inside f-strings with single quotes. Use `f"string {os.getenv('VAR')}"` or `f'string {os.getenv("VAR")}'`.

### 3. Application Definition - Creating Our Veza Application Model

```python
app = CustomApplication(name='Sample App', application_type='PagerDuty')
```

**What's Happening Here:**
We're creating a representation of PagerDuty as an application within Veza's authorization model.

**Detailed Explanation:**
- **`CustomApplication`**: A template class that represents any external application in Veza
- **`name='Sample App'`**: Human-readable name that appears in Veza's dashboard
- **`application_type='PagerDuty'`**: Categorizes this as a PagerDuty integration

**Think of it like:** Creating a new folder in Veza labeled "PagerDuty" where all the user and permission data will be organized.

**Best Practices:**
- Use descriptive names that your team will recognize
- Keep application_type consistent across environments
- Consider naming conventions like "PagerDuty-Production" vs "PagerDuty-Dev"

### 4. Custom Properties - Defining Extra Data Fields

**Official Veza Guidance:** According to [Veza's OAA documentation](https://veza.com/blog/intelligent-access-for-custom-apps-getting-started-with-vezas-open-authorization-api/), the Custom Application Template is a graph model made up of nodes (representing entities like Local Users, Local Groups, Local Roles, Permissions, and Resources) and edges (associations between nodes). You read the graph from left to right: Local users on the left, traversing via relations to the resources they can access on the right.

```python
# User properties - Extra information about each user
app.property_definitions.define_local_user_property('email', OAAPropertyType.STRING)
app.property_definitions.define_local_user_property('is_billed', OAAPropertyType.BOOLEAN)

# Resource properties - Extra information about each team
app.property_definitions.define_resource_property('team', 'pagerduty_id', OAAPropertyType.STRING)
app.property_definitions.define_resource_property('team', 'summary', OAAPropertyType.STRING)
app.property_definitions.define_resource_property('team', 'default_role', OAAPropertyType.STRING)
```

**What's Happening Here:**
We're defining custom fields that will store additional information beyond Veza's standard user and resource fields.

**User Properties Explained:**
```python
app.property_definitions.define_local_user_property('email', OAAPropertyType.STRING)
```
- **Purpose**: Store the user's email address
- **Type**: STRING (text data)
- **Usage**: Later used for identity linking and contact information

```python
app.property_definitions.define_local_user_property('is_billed', OAAPropertyType.BOOLEAN)
```
- **Purpose**: Track whether this user is a paid/billed user in PagerDuty
- **Type**: BOOLEAN (true/false)
- **Usage**: Helps identify active vs inactive users

**Resource Properties Explained:**
```python
app.property_definitions.define_resource_property('team', 'pagerduty_id', OAAPropertyType.STRING)
```
- **Resource Type**: 'team' (we'll create team resources later)
- **Property Name**: 'pagerduty_id' 
- **Purpose**: Store PagerDuty's internal team ID for reference
- **Type**: STRING

**Available Property Types:**
- `OAAPropertyType.STRING`: Text data
- `OAAPropertyType.BOOLEAN`: True/False values
- `OAAPropertyType.NUMBER`: Numeric data
- `OAAPropertyType.DATETIME`: Date and time values

**Teaching Point:** Custom properties are like adding extra columns to a database table. They help provide richer context for authorization analysis.

### 5. Permission System - Mapping PagerDuty Roles to Veza Permissions

```python
# Define what each PagerDuty role can do in Veza's permission language
app.add_custom_permission('admin', permissions=[
    OAAPermission.DataWrite,     # Can modify data
    OAAPermission.DataRead,      # Can view data  
    OAAPermission.DataDelete,    # Can delete data
    OAAPermission.MetadataRead,  # Can view metadata
    OAAPermission.MetadataWrite  # Can modify metadata
])

app.add_custom_permission('limited_user', permissions=[
    OAAPermission.DataRead,      # Can only view data
    OAAPermission.MetadataRead   # Can only view metadata
])

app.add_custom_permission('manager', permissions=[
    OAAPermission.DataWrite,     # Can modify data
    OAAPermission.DataRead,      # Can view data
    OAAPermission.MetadataWrite, # Can modify metadata
    OAAPermission.MetadataRead   # Can view metadata
])
# ... more permission definitions
```

**What's Happening Here:**
We're creating a translation layer between PagerDuty's role names and Veza's standardized permission model.

**Veza's Standard Permission Types (Effective Permissions):**
According to [Veza's official documentation](https://veza.com/blog/intelligent-access-for-custom-apps-getting-started-with-vezas-open-authorization-api/), permissions are normalized into "Effective Permissions" using the CRUDMNU model:
- **`DataRead`** (R): Can view the actual data/content
- **`DataWrite`** (U): Can modify the actual data/content  
- **`DataDelete`** (D): Can delete data/content
- **`MetadataRead`** (M): Can view information *about* the data (properties, settings)
- **`MetadataWrite`** (M): Can modify information *about* the data
- **`DataCreate`** (C): Can create new data/content
- **`NonDataAccess`** (N): Access that doesn't involve data (like login permissions)
- **`Uncategorized`** (U): Permissions that don't fit other categories

**Real-World Example:**
Think of a document management system:
- **DataRead**: Can read the document content
- **DataWrite**: Can edit the document content
- **DataDelete**: Can delete the document
- **MetadataRead**: Can see document properties (author, creation date, tags)
- **MetadataWrite**: Can change document properties

**Why This Mapping Matters:**
- **Standardization**: All applications in Veza use the same permission vocabulary
- **Comparison**: You can compare permissions across different systems
- **Analysis**: Veza can identify over-privileged users across all systems

**Teaching Point:** This is a common pattern in integration work - translating between different systems' vocabularies.

### 6. Role Definition - Creating Named Role Bundles

```python
# Bundle permissions into named roles that match PagerDuty's role names
app.add_local_role('Global Admin', unique_id='admin', permissions=['admin'])
app.add_local_role('Responder', unique_id='limited_user', permissions=['limited_user'])
app.add_local_role('Observer', unique_id='observer', permissions=['observer'])
app.add_local_role('Account Owner', unique_id='owner', permissions=['owner'])
# ... more role definitions
```

**What's Happening Here:**
We're creating named roles that bundle the custom permissions we defined earlier.

**Parameter Breakdown:**
- **First Parameter**: Human-readable role name (appears in Veza UI)
- **`unique_id`**: Internal identifier used by the code
- **`permissions`**: List of custom permission names we defined in step 5

**Example Explained:**
```python
app.add_local_role('Global Admin', unique_id='admin', permissions=['admin'])
```
- **Display Name**: "Global Admin" (what users see)
- **Internal ID**: 'admin' (what the code uses)
- **Permissions**: ['admin'] (references the 'admin' permission we defined earlier)

**Important Note:** The script has a bug - "Responder" role is defined twice with different unique_ids:
```python
app.add_local_role('Responder', unique_id='limited_user', permissions=['limited_user'])
# ... later in the code ...
app.add_local_role('Responder', unique_id='responder', permissions=['responder'])
```

**Teaching Points:**
- Roles are collections of permissions
- The unique_id must match what PagerDuty's API returns
- Always check for duplicates in role definitions

### 7. Data Extraction and Mapping - Getting Data from PagerDuty

```python
# Fetch all users from PagerDuty
response = requests.get('https://api.pagerduty.com/users?limit=100', headers=headers)
response = response.json()  # Convert JSON response to Python dictionary

for user in response['users']:
    # Create a new user in our Veza application model
    new_user = app.add_local_user(
        user.get('name'),                    # User's display name
        unique_id=user.get('id'),            # PagerDuty's internal user ID
        identities=[user.get('email')]       # Email for identity linking
    )
    
    # Assign the user's role at the application level
    new_user.add_role(user.get('role'), apply_to_application=True)
    
    # Store additional user information in custom properties
    new_user.set_property('email', user.get('email'))
    new_user.set_property('is_billed', user.get('billed'))

# Fetch all teams from PagerDuty
response = requests.get('https://api.pagerduty.com/teams?limit=100', headers=headers)
teams = response.json()['teams']

for team in teams:
    # Create a group (collection of users) for each PagerDuty team
    app.add_local_group(team.get('name'), unique_id=team.get("id"))
```

**What's Happening Here:**
This is where we actually pull data from PagerDuty and convert it into Veza's format.

**User Processing Deep Dive:**

1. **API Call**: `requests.get('https://api.pagerduty.com/users?limit=100', headers=headers)`
   - **URL**: PagerDuty's users endpoint
   - **Query Parameter**: `limit=100` (maximum 100 users per request)
   - **Headers**: Our authentication headers from step 2

2. **JSON Parsing**: `response.json()`
   - Converts the HTTP response into a Python dictionary
   - PagerDuty returns: `{"users": [{"id": "...", "name": "...", "email": "..."}, ...]}`

3. **User Creation**: `app.add_local_user(...)`
   - **`user.get('name')`**: Safe way to get the name (returns None if missing)
   - **`unique_id=user.get('id')`**: PagerDuty's internal ID (like "P123ABC")
   - **`identities=[user.get('email')]`**: List of email addresses for identity linking

4. **Role Assignment**: `new_user.add_role(user.get('role'), apply_to_application=True)`
   - **`user.get('role')`**: PagerDuty role name (like "admin", "user")
   - **`apply_to_application=True`**: This role applies to the entire PagerDuty application

5. **Custom Properties**: 
   ```python
   new_user.set_property('email', user.get('email'))
   new_user.set_property('is_billed', user.get('billed'))
   ```
   - Stores the custom properties we defined in step 4

**Team Processing:**
- Similar to users but creates "groups" instead
- Groups represent collections of users (teams in this case)
- Will be used later to show team membership

**Limitation Alert:** The `limit=100` means only 100 users/teams are processed. Large organizations need pagination.

### 8. Resource Creation - Defining What Can Be Accessed

**Veza's Resource Philosophy:** As noted in [Veza's official guide](https://veza.com/blog/intelligent-access-for-custom-apps-getting-started-with-vezas-open-authorization-api/), resources can be anything you want to track access to. For example:
- A fileshare app might list each folder or individual files as resources
- A database might list tables and views as resources  
- PagerDuty treats teams as resources that users can have permissions on

```python
# Convert each PagerDuty team into a Veza "resource" (something that can be accessed)
for team in teams:        
    # Create a resource representing this team
    resource = app.add_resource(team.get('name'), resource_type='team')
    
    # Set the description (truncated to 255 characters due to Veza limits)
    resource.description = team.get('description')[:255] if team.get('description') else None
    
    # Store team-specific information in custom properties
    resource.set_property('pagerduty_id', team.get('id'))
    resource.set_property('summary', team.get('summary'))
    resource.set_property('default_role', team.get('default_role'))
```

**What's Happening Here:**
We're defining what users can have permissions *on*. In this case, PagerDuty teams are treated as resources that users can access.

**Detailed Breakdown:**

1. **Resource Creation**: `app.add_resource(team.get('name'), resource_type='team')`
   - **First Parameter**: Resource name (team name from PagerDuty)
   - **`resource_type='team'`**: Category of resource (matches our property definitions)

2. **Description Handling**:
   ```python
   resource.description = team.get('description')[:255] if team.get('description') else None
   ```
   - **Conditional Logic**: Only set description if it exists
   - **Truncation**: `[:255]` limits to 255 characters (Veza requirement)
   - **Fallback**: `else None` if no description exists

3. **Custom Properties**: Store additional team metadata
   - **`pagerduty_id`**: PagerDuty's internal team ID (for API calls later)
   - **`summary`**: Team summary from PagerDuty
   - **`default_role`**: Default role for team members

**Conceptual Understanding:**
- **Users**: People who can access things
- **Resources**: Things that can be accessed
- **Permissions**: What users can do with resources

**Teaching Point:** Resources represent the "what" in "who can do what to what." They're the objects of authorization.

### 9. Permission Assignment - Connecting Users to Resources

```python
# For each team resource we created...
for team in app.resources:
    resource = app.resources[team]
    team_id = resource.properties.get('pagerduty_id')  # Get PagerDuty team ID
    
    # Fetch team members from PagerDuty
    response = requests.get(f'https://api.pagerduty.com/teams/{team_id}/members', headers=headers)
    response = response.json()
    
    # Process each team member
    for member in response['members']:
        # Give the user their team-specific role on this team resource
        app.local_users[member['user']['id']].add_role(
            member['role'],           # Role name from PagerDuty
            resources=[resource]      # Apply only to this specific team
        )
        
        # Add the user to the team group
        app.local_users[member['user']['id']].add_group(team_id)
```

**What's Happening Here:**
This is where we create the actual authorization relationships - who has what role on which teams.

**Step-by-Step Process:**

1. **Iterate Through Resources**: `for team in app.resources:`
   - Goes through each team resource we created in step 8

2. **Get Team ID**: `team_id = resource.properties.get('pagerduty_id')`
   - Retrieves the PagerDuty team ID we stored as a custom property
   - This ID is needed for the API call to get team members

3. **API Call for Members**: 
   ```python
   response = requests.get(f'https://api.pagerduty.com/teams/{team_id}/members', headers=headers)
   ```
   - **f-string**: Inserts the team_id into the URL
   - **Endpoint**: Gets all members of a specific team
   - **Returns**: List of team members with their roles

4. **Resource-Specific Role Assignment**:
   ```python
   app.local_users[member['user']['id']].add_role(member['role'], resources=[resource])
   ```
   - **`app.local_users[member['user']['id']]`**: Finds the user we created earlier
   - **`member['role']`**: The user's role on this specific team
   - **`resources=[resource]`**: Applies only to this team (not application-wide)

5. **Group Membership**:
   ```python
   app.local_users[member['user']['id']].add_group(team_id)
   ```
   - Adds the user to the team group
   - Shows organizational structure in Veza

**Key Concept - Two Types of Roles:**
- **Application-Level**: User has this role across all of PagerDuty (step 7)
- **Resource-Level**: User has this role only on specific teams (step 9)

**Real-World Example:**
- Alice might be a "User" at the application level (can access PagerDuty)
- But she's a "Manager" on the "Database Team" resource
- And an "Observer" on the "Security Team" resource

**Teaching Point:** This creates a granular permission model where users can have different roles on different resources.

### 10. Data Transmission - Sending Everything to Veza

```python
# Define how this integration appears in Veza
provider_name = 'Lab-PagerDuty'

# Create connection to Veza
veza_con = OAAClient(url=veza_url, api_key=veza_api_key)

# Get or create a provider (data source) in Veza
provider = veza_con.get_provider(provider_name)
if not provider:
    provider = veza_con.create_provider(provider_name, 'application')

# Send all our data to Veza
try:
    response = veza_con.push_application(
        provider_name,                                           # Which provider
        data_source_name=f'{app.name} ({app.application_type})', # Data source name
        application_object=app,                                  # Our complete app model
        save_json=False                                          # Don't save local copy
    )
    
    # Handle warnings (non-fatal issues)
    if response.get('warnings', None):
        print('-- Push succeeded with warnings:')
        for e in response['warnings']:
            print(f'  - {e}')
            
except OAAClientError as e:
    # Handle errors
    print(f'-- Error: {e.error}: {e.message} ({e.status_code})', file=sys.stderr)
    if hasattr(e, 'details'):
        for d in e.details:
            print(f'  -- {d}', file=sys.stderr)
```

**What's Happening Here:**
This final step packages up all the data we've collected and sends it to Veza for processing.

**Detailed Breakdown:**

1. **Provider Setup**:
   ```python
   provider_name = 'Lab-PagerDuty'
   ```
   - **Provider**: A data source in Veza (like a folder for all PagerDuty data)
   - **Naming**: Use descriptive names that indicate environment and system

2. **Veza Connection**:
   ```python
   veza_con = OAAClient(url=veza_url, api_key=veza_api_key)
   ```
   - Creates authenticated connection using credentials from step 2

3. **Provider Management**:
   ```python
   provider = veza_con.get_provider(provider_name)
   if not provider:
       provider = veza_con.create_provider(provider_name, 'application')
   ```
   - **Try to Get**: Check if provider already exists
   - **Create if Missing**: First-time setup creates the provider
   - **Type 'application'**: Indicates this is an application integration

4. **Data Upload**:
   ```python
   response = veza_con.push_application(
       provider_name,                                           # Which data source
       data_source_name=f'{app.name} ({app.application_type})', # Display name
       application_object=app,                                  # All our data
       save_json=False                                          # Don't save locally
   )
   ```
   - **`application_object=app`**: Sends our complete application model
   - **`save_json=False`**: Doesn't create a local JSON file (set to True for debugging)

5. **Warning Handling**:
   ```python
   if response.get('warnings', None):
       print('-- Push succeeded with warnings:')
       for e in response['warnings']:
           print(f'  - {e}')
   ```
   - **Warnings**: Non-fatal issues (like unresolved email addresses)
   - **Common Warning**: "Cannot find identity by names" (email doesn't match IdP)

6. **Error Handling**:
   ```python
   except OAAClientError as e:
       print(f'-- Error: {e.error}: {e.message} ({e.status_code})', file=sys.stderr)
   ```
   - **`OAAClientError`**: Specific exception for Veza API errors
   - **Error Details**: Provides specific error messages for debugging
   - **`file=sys.stderr`**: Sends error output to stderr (standard error stream)

**Success Indicators:**
- **No exceptions**: Data uploaded successfully
- **Warnings only**: Data uploaded but with some issues (usually identity linking)
- **"Push succeeded with warnings"**: Everything worked, minor issues noted

**Teaching Points:**
- Always handle both success and error cases
- Warnings are informational and usually acceptable
- Error handling should provide actionable information for debugging

### Summary of the Complete Flow

1. **Setup** (Steps 1-3): Import tools, load config, create application model
2. **Define Structure** (Steps 4-6): Set up properties, permissions, and roles
3. **Extract Data** (Steps 7-8): Pull users and teams from PagerDuty, create resources
4. **Map Relationships** (Step 9): Connect users to teams with specific roles
5. **Transmit** (Step 10): Send everything to Veza for analysis

This creates a complete authorization model that Veza can use for compliance reporting, access reviews, and security analysis.

---

## Setup Instructions

### 1. Environment Variables
Create a `.env` file in your project root:
```bash
VEZA_URL=https://your-veza-instance.com
VEZA_API_KEY=your_veza_api_key_here
PAGERDUTY_API_KEY=your_pagerduty_api_key_here
```

### 2. Getting PagerDuty API Key
1. Log into PagerDuty as an admin
2. Go to Configuration → API Access
3. Create a new API key
4. Choose "Read-only" permissions
5. Copy the generated key

### 3. Getting Veza API Key
1. Log into your Veza instance
2. Go to Settings → API Keys
3. Create a new API key
4. Copy the key and Veza URL

### 4. Required Python Packages
```bash
pip install oaaclient requests python-dotenv
```

**Package Details:**

#### `oaaclient` (Veza Open Authorization API Client)
- **Purpose**: Official Python SDK for integrating with Veza's authorization platform
- **What it does**: 
  - Provides classes and methods to build custom application models
  - Handles authentication and communication with Veza's API
  - Offers pre-built templates for common authorization patterns
  - Manages data validation and payload formatting
- **Key components used in this script**:
  - `OAAClient`: Main client for connecting to Veza API
  - `CustomApplication`: Template for defining custom applications
  - `OAAPropertyType`: Defines data types for custom properties (STRING, BOOLEAN, etc.)
  - `OAAPermission`: Standard permission types (DataRead, DataWrite, etc.)
  - `OAAClientError`: Exception handling for API errors

#### `requests` (HTTP Library)
- **Purpose**: Industry-standard Python library for making HTTP requests
- **What it does**:
  - Sends GET/POST/PUT/DELETE requests to REST APIs
  - Handles HTTP authentication, headers, and response parsing
  - Manages sessions, cookies, and connection pooling
  - Provides built-in JSON encoding/decoding
- **How it's used in this script**:
  - Makes authenticated calls to PagerDuty's REST API
  - Retrieves user, team, and membership data from PagerDuty
  - Handles API pagination and error responses
  - Formats authentication headers for PagerDuty's token-based auth

#### `python-dotenv` (Environment Variable Management)
- **Purpose**: Loads environment variables from `.env` files into your Python application
- **What it does**:
  - Reads key-value pairs from `.env` files
  - Makes environment variables available via `os.getenv()`
  - Supports different environments (dev, staging, prod)
  - Keeps sensitive configuration separate from source code
- **Security benefits**:
  - Prevents hardcoding API keys and secrets in source code
  - Allows different configurations per environment
  - Keeps sensitive data out of version control
  - Follows the "12-factor app" methodology for configuration

**Installation in Virtual Environment (Recommended):**
```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate     # On Windows

# Install packages
pip install oaaclient requests python-dotenv
```

**Alternative Installation Methods:**
```bash
# Install globally (not recommended for production)
pip3 install oaaclient requests python-dotenv

# Install with specific versions for reproducibility
pip install oaaclient==1.1.14 requests==2.32.4 python-dotenv==1.1.1

# Install from requirements.txt
echo "oaaclient>=1.1.0" > requirements.txt
echo "requests>=2.28.0" >> requirements.txt
echo "python-dotenv>=1.0.0" >> requirements.txt
pip install -r requirements.txt
```

---

## Authentication Explained

### HTTP Headers
```python
headers = {
    'Accept': 'application/json',
    'Authorization': f'Token token={os.getenv('PAGERDUTY_API_KEY')}'
}
```

**Header Breakdown:**
- `Accept: application/json`: Requests JSON response format
- `Authorization: Token token=YOUR_KEY`: PagerDuty's token-based authentication

### Token-Based Authentication
- **What**: A temporary digital key proving authorization
- **How**: Include token in every API request
- **Security**: Tokens validate identity and permissions
- **Format**: `Token token=your_actual_key_here`

### Security Best Practices
- Store API keys in environment variables (not in code)
- Use read-only API keys when possible
- Never commit `.env` files to version control
- Rotate API keys regularly

---

## Common Questions & Answers

### Basic Understanding

**Q: What does this script actually do?**
A: Extracts user, team, and permission data from PagerDuty and sends it to Veza for centralized authorization visibility.

**Q: Why would someone need this integration?**
A: For security compliance, access reviews, risk management, and centralized visibility across systems.

**Q: What's the difference between users, groups, and resources?**
A: Users = individual people, Groups = PagerDuty teams, Resources = things that can be accessed (teams in this case).

### Technical Setup

**Q: What environment variables do I need?**
A: `VEZA_URL`, `VEZA_API_KEY`, and `PAGERDUTY_API_KEY`

**Q: How do I get a PagerDuty API key?**
A: Admin dashboard → Configuration → API Access → Create new key

**Q: What permissions does this script need?**
A: PagerDuty: Read access to users/teams. Veza: Create/update providers and push data.

### Data Flow

**Q: What data gets transferred?**
A: User data (names, emails, roles), team data (names, descriptions), membership data, and permission mappings.

**Q: How often should this script run?**
A: Daily for most organizations, weekly for smaller ones, or on-demand for testing.

**Q: Does this script modify PagerDuty?**
A: No, it's read-only. Only reads from PagerDuty and sends to Veza.

### Scalability

**Q: Why is there a limit of 100 users/teams?**
A: Simple implementation. Production versions need pagination for larger datasets.

**Q: How handle more than 100 users/teams?**
A: Implement pagination with offset/limit parameters in API calls.

**Q: What if PagerDuty API is down?**
A: Script would crash. Production versions need retry logic and error handling.

### Permissions

**Q: How do PagerDuty roles map to Veza permissions?**
A: Script creates custom mappings (Admin = all permissions, User = read/metadata, etc.)

**Q: Can I customize permission mappings?**
A: Yes, modify the `add_custom_permission()` calls to match your needs.

**Q: What's the difference between application-level and resource-level permissions?**
A: Application-level = across entire PagerDuty, Resource-level = specific teams only.

### Troubleshooting

**Q: What does "Push succeeded with warnings" mean?**
A: Data imported successfully but with issues like unresolved email addresses or missing data.

**Q: Why might authentication fail?**
A: Incorrect API keys, expired keys, insufficient permissions, or wrong URL format.

**Q: What if I see duplicate users/resources?**
A: Usually from running script multiple times or API returning duplicates.

### Security

**Q: Is storing API keys in environment variables safe?**
A: Yes, it's a security best practice. Keys aren't in source code and can't be accidentally committed.

**Q: What sensitive data does this handle?**
A: API keys, email addresses, user names, and team membership data.

### Customization

**Q: How add custom properties?**
A: Use `define_local_user_property()` or `define_resource_property()` then `set_property()`.

**Q: Can I integrate other systems?**
A: Yes! Replace PagerDuty API calls with your system's API and adjust data mapping.

**Q: How do I test safely?**
A: Use test environments, read-only API keys, small data subsets, and separate provider names.

### Performance

**Q: How long does this take to run?**
A: Small org (10-50 users): 5-30 seconds. Medium (100-500): 1-5 minutes. Large (1000+): 10+ minutes.

**Q: Can I run this in parallel?**
A: Not recommended. Each run replaces previous data and could cause inconsistencies.

---

## Troubleshooting

### Common Errors

**Authentication Errors**
- Check API keys in `.env` file
- Verify API key permissions
- Ensure correct Veza URL format
- Check for expired keys

**API Rate Limits**
- Implement delays between requests
- Use pagination for large datasets
- Monitor API usage limits

**Data Mapping Issues**
- Verify PagerDuty role names match script expectations
- Check for missing required fields
- Validate email address formats

### Debugging Tips

**Enable JSON Payload Inspection**
```python
# Uncomment this line to see the data being sent
print(json.dumps(app.get_payload()))
```

**Add Logging**
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

**Test with Small Dataset**
- Use `limit=10` in API calls for testing
- Create test provider in Veza
- Verify data mapping before full sync

---

## Best Practices

### Security
- Use environment variables for secrets
- Implement least-privilege API access
- Regular API key rotation
- Secure `.env` file storage

### Performance
- Implement pagination for large datasets
- Add retry logic with exponential backoff
- Monitor API rate limits
- Cache data when appropriate

### Error Handling
- Comprehensive try-catch blocks
- Detailed error logging
- Graceful degradation
- User-friendly error messages

### Maintenance
- Regular testing of integration
- Monitor for API changes
- Update permission mappings as needed
- Document customizations

---

## Customization Guide

### Adding Custom Properties
```python
# For users
app.property_definitions.define_local_user_property('department', OAAPropertyType.STRING)
app.property_definitions.define_local_user_property('hire_date', OAAPropertyType.STRING)

# For resources
app.property_definitions.define_resource_property('team', 'cost_center', OAAPropertyType.STRING)

# Set the properties
new_user.set_property('department', user.get('department'))
```

### Custom Permission Mappings
```python
# Modify existing permissions
app.add_custom_permission('admin', permissions=[OAAPermission.DataRead, OAAPermission.MetadataRead])

# Add new custom permissions
app.add_custom_permission('custom_role', permissions=[OAAPermission.DataWrite])
```

### Pagination Implementation
```python
def get_all_users():
    users = []
    offset = 0
    limit = 100
    
    while True:
        response = requests.get(f'https://api.pagerduty.com/users?limit={limit}&offset={offset}', headers=headers)
        data = response.json()
        users.extend(data['users'])
        
        if len(data['users']) < limit:  # Last page
            break
        offset += limit
    
    return users
```

### Retry Logic
```python
import time
from requests.exceptions import RequestException

def make_request_with_retry(url, headers, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response
        except RequestException as e:
            if attempt == max_retries - 1:
                raise e
            time.sleep(2 ** attempt)  # Exponential backoff
```

---

## Known Issues and Limitations

### Current Limitations
1. **100-item limit**: API calls limited to 100 users/teams
2. **No pagination**: Large organizations won't sync completely
3. **Basic error handling**: Script crashes on API failures
4. **Duplicate role**: "Responder" role defined twice
5. **Typo**: "Golbal Admin" should be "Global Admin"

### Recommended Improvements
1. Implement pagination for large datasets
2. Add comprehensive retry logic
3. Improve error handling and logging
4. Fix duplicate role definitions
5. Add data validation
6. Implement incremental sync capabilities

---

## Resources

### Documentation
- [Veza OAA Client Documentation](https://docs.veza.com)
- [PagerDuty API Documentation](https://developer.pagerduty.com)
- [Python Requests Library](https://requests.readthedocs.io)

### Support
- Veza Support: [support.veza.com](https://support.veza.com)
- PagerDuty Support: [support.pagerduty.com](https://support.pagerduty.com)

---

## Official Veza Resources and Next Steps

### Veza's Developer Ecosystem
According to [Veza's blog post](https://veza.com/blog/intelligent-access-for-custom-apps-getting-started-with-vezas-open-authorization-api/), they provide extensive resources for developers:

- **GitHub Repository**: Check out [Veza's GitHub repo](https://github.com/Veza) for more OAA examples, documentation, and developer tools
- **200+ Built-in Integrations**: Veza already supports over 200 systems out-of-the-box
- **Extensible APIs**: Integration with other security platforms for custom automation
- **Developer Community**: Active community contributing examples and best practices

### Beyond Basic Integration
Once you have a working PagerDuty integration, Veza enables advanced capabilities:

#### Access Intelligence
- **Risk Identification**: Visualize overprivileged and misconfigured permissions
- **Segregation of Duties**: Enforce SoD policies across systems
- **Event-Driven Architecture**: Automated alerts and remediation when access changes

#### Access Operations
- **Access Search**: Query access patterns across all connected systems
- **Access Monitoring**: Real-time monitoring of who accesses what resources
- **Access Workflows**: Automated provisioning and deprovisioning
- **Lifecycle Management**: Employee onboarding/offboarding automation
- **Access Requests**: Self-service access request workflows

### Production Considerations
When moving from this tutorial to production:

1. **Scale Handling**: Implement pagination for organizations with >100 users/teams
2. **Error Resilience**: Add comprehensive retry logic and error handling
3. **Monitoring**: Set up logging and alerting for integration health
4. **Security**: Rotate API keys regularly and use least-privilege access
5. **Testing**: Implement automated testing for integration reliability

### Learning Path
1. **Start Here**: Complete this PagerDuty integration tutorial
2. **Explore**: Check other OAA examples in Veza's GitHub repository
3. **Expand**: Integrate additional custom applications in your environment
4. **Optimize**: Implement advanced features like automated remediation
5. **Scale**: Build a comprehensive authorization graph across all systems

---

*This guide covers the complete PagerDuty to Veza integration, including setup, troubleshooting, and customization. Use this as a reference for implementing and maintaining the integration. For the latest updates and additional resources, visit [Veza's official OAA documentation](https://veza.com/blog/intelligent-access-for-custom-apps-getting-started-with-vezas-open-authorization-api/).*
