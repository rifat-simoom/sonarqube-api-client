import requests
from collections import defaultdict
import pandas as pd
import matplotlib.pyplot as plt

def fetch_sonarqube_data(api_url, token, project_key):
    headers = {'Authorization': f'Bearer {token}'}
    all_hotspots = []
    all_components = []
    page = 1
    page_size = 500
    
    while True:
        params = {
            'p': page,
            'ps': page_size,
            'project': project_key
        }
        
        response = requests.get(api_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        if not data.get('hotspots') or len(data['hotspots']) == 0:
            break
            
        all_hotspots.extend(data['hotspots'])
        all_components.extend(data.get('components', []))
        
        print(f"Fetched page {page} with {len(data['hotspots'])} hotspots")
        
        paging = data.get('paging', {})
        if paging.get('pageIndex', 0) * paging.get('pageSize', 0) >= paging.get('total', 0):
            break
            
        page += 1
    
    print(f"Total hotspots fetched: {len(all_hotspots)}")
    
    return {
        'paging': {
            'pageIndex': page,
            'pageSize': page_size,
            'total': len(all_hotspots)
        },
        'hotspots': all_hotspots,
        'components': all_components
    }

def process_hotspots(data):
    components = {comp['key']: comp for comp in data.get('components', [])}
    
    vulnerabilities = []
    severity_counts = defaultdict(int)
    status_counts = defaultdict(int)
    category_counts = defaultdict(int)
    
    for hotspot in data.get('hotspots', []):
        component = components.get(hotspot['component'], {})
        severity = hotspot.get('vulnerabilityProbability', 'N/A')
        status = hotspot.get('status', 'UNKNOWN')
        category = hotspot.get('securityCategory', 'UNCATEGORIZED')
        
        vulnerabilities.append({
            'Rule': hotspot['ruleKey'],
            'Severity': severity,
            'Component': component.get('longName', hotspot['component']),
            'Line': hotspot['line'],
            'Description': hotspot['message'],
            'Status': status,
            'Category': category
        })
        
        severity_counts[severity] += 1
        status_counts[status] += 1
        category_counts[category] += 1
    
    return vulnerabilities, severity_counts, status_counts, category_counts


def create_excel_report(filename, vulnerabilities, severity_counts, status_counts, category_counts):
    # Create DataFrame from vulnerabilities
    df = pd.DataFrame(vulnerabilities)

    # Create Excel writer
    writer = pd.ExcelWriter(filename, engine='xlsxwriter')
    df.to_excel(writer, sheet_name='Vulnerabilities', index=False)

    # Get workbook and worksheet objects
    workbook = writer.book
    vuln_sheet = writer.sheets['Vulnerabilities']
    worksheet = workbook.add_worksheet('Security Summary')
    writer.sheets['Security Summary'] = worksheet

    # Define styles
    header_format = workbook.add_format({
        'bold': True,
        'font_name': 'Calibri',
        'font_size': 11,
        'text_wrap': True,
        'valign': 'top',
        'fg_color': '#4472C4',
        'font_color': 'white',
        'border': 1
    })

    cell_format = workbook.add_format({
        'font_name': 'Calibri',
        'font_size': 10,
        'border': 1
    })

    alt_row_format = workbook.add_format({
        'font_name': 'Calibri',
        'font_size': 10,
        'bg_color': '#F2F2F2',
        'border': 1
    })

    # Apply formatting to Vulnerabilities sheet
    for col_num, column_name in enumerate(df.columns):
        vuln_sheet.write(0, col_num, column_name, header_format)

    for row_num in range(1, len(df) + 1):
        for col_num in range(len(df.columns)):
            if row_num % 2 == 0:
                vuln_sheet.write(row_num, col_num, df.iloc[row_num - 1, col_num], alt_row_format)
            else:
                vuln_sheet.write(row_num, col_num, df.iloc[row_num - 1, col_num], cell_format)

    # Auto-adjust column widths with better padding
    for col_idx, col in enumerate(df.columns):
        max_len = max(df[col].astype(str).map(len).max(), len(col)) + 4  # Increased padding
        vuln_sheet.set_column(col_idx, col_idx, max_len, cell_format)

    # Write data to Security Summary sheet with improved formatting
    # Severity table
    severity_df = pd.DataFrame(list(severity_counts.items()), columns=['Severity', 'Count'])
    severity_df.to_excel(writer, sheet_name='Security Summary', startrow=0, index=False, header=False)
    for col_num, column_name in enumerate(severity_df.columns):
        worksheet.write(0, col_num, column_name, header_format)
    for row_num in range(len(severity_df)):
        for col_num in range(len(severity_df.columns)):
            worksheet.write(row_num + 1, col_num, severity_df.iloc[row_num, col_num], cell_format)

    # Status table
    status_df = pd.DataFrame(list(status_counts.items()), columns=['Status', 'Count'])
    start_row = len(severity_df) + 3
    status_df.to_excel(writer, sheet_name='Security Summary', startrow=start_row, index=False, header=False)
    for col_num, column_name in enumerate(status_df.columns):
        worksheet.write(start_row, col_num, column_name, header_format)
    for row_num in range(len(status_df)):
        for col_num in range(len(status_df.columns)):
            worksheet.write(start_row + row_num + 1, col_num, status_df.iloc[row_num, col_num], cell_format)

    # Category table
    category_df = pd.DataFrame(list(category_counts.items()), columns=['Category', 'Count'])
    start_row += len(status_df) + 3
    category_df.to_excel(writer, sheet_name='Security Summary', startrow=start_row, index=False, header=False)
    for col_num, column_name in enumerate(category_df.columns):
        worksheet.write(start_row, col_num, column_name, header_format)
    for row_num in range(len(category_df)):
        for col_num in range(len(category_df.columns)):
            worksheet.write(start_row + row_num + 1, col_num, category_df.iloc[row_num, col_num], cell_format)

    # Create and format pie chart
    chart = workbook.add_chart({'type': 'pie'})
    chart.add_series({
        'name': 'Severity Distribution',
        'categories': ['Security Summary', 1, 0, len(severity_df), 0],
        'values': ['Security Summary', 1, 1, len(severity_df), 1],
        'data_labels': {
            'percentage': True,
            'category': True,
            'leader_lines': True,
            'font': {'name': 'Calibri', 'size': 9}
        }
    })
    chart.set_title({
        'name': 'Vulnerability Severity Distribution',
        'name_font': {'name': 'Calibri', 'size': 11, 'bold': True}
    })
    chart.set_legend({'font': {'name': 'Calibri', 'size': 9}})
    chart.set_style(10)
    worksheet.insert_chart('E2', chart, {'x_scale': 1.2, 'y_scale': 1.2})

    # Set consistent column widths for Security Summary
    worksheet.set_column('A:A', 25, cell_format)
    worksheet.set_column('B:B', 10, cell_format)

    writer.close()

if __name__ == "__main__":
    # Configuration
    SONARQUBE_URL = "http://localhost:9000/api/hotspots/search"
    TOKEN = "squ_cce5da16061602289b31f083eac8329936b78e5b"
    PROJECT_KEY = "pf"
    EXCEL_OUTPUT = "security_hotspots_report.xlsx"

    # Fetch and process data
    data = fetch_sonarqube_data(SONARQUBE_URL, TOKEN, PROJECT_KEY)
    vulnerabilities, severity_counts, status_counts, category_counts = process_hotspots(data)
    
    # Generate reports
    create_excel_report(EXCEL_OUTPUT, vulnerabilities, severity_counts, status_counts, category_counts)
    
    print(f"Excel report generated: {EXCEL_OUTPUT}")
