import streamlit as st
import os
import pandas as pd
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage
from langchain_community.utilities import SQLDatabase

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="Pro Secure SQL Assistant", page_icon="🛡️", layout="wide")
st.title("🛡️ Professional Secure AI Database Analyzer")
st.markdown("This system translates Persian or English into secure T-SQL queries.")

# --- API KEY & DATABASE CONNECTION ---
# Replace with your actual Groq API Key
os.environ["GROQ_API_KEY"] = "YOUR_GROQ_API_KEY_HERE"

@st.cache_resource
def init_connection():
    # Connection string for SQL Server - Windows Authentication (Trusted Connection)
    conn_str = "mssql+pyodbc://@localhost/Employee?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes"
    return SQLDatabase.from_uri(conn_str)

db = init_connection()

# --- AI MODEL SETUP (Llama 3.3 70B) ---
# Using the most advanced and stable model for logic-heavy tasks
chat_model = ChatGroq(model_name="llama-3.3-70b-versatile", temperature=0)

def generate_sql(question):
    """
    Translates Natural Language to T-SQL with strict multi-layer security filtering.
    """
    schema = db.get_table_info()
    
    system_prompt = (
        f"You are a Microsoft SQL Server Expert (T-SQL).\n"
        f"Database Schema:\n{schema}\n\n"
        "STRICT T-SQL RULES:\n"
        "1. AMBIGUITY: Always prefix columns with table names (e.g., employees.emp_no).\n"
        "2. OVERFLOW: Always use CAST(salary AS BIGINT) for SUM/AVG calculations.\n"
        "3. SECURITY: Only generate SELECT statements. Forbidden: DROP, DELETE, INSERT, UPDATE, TRUNCATE.\n"
        "4. SYNTAX: Use 'SELECT TOP X' instead of 'LIMIT'.\n"
        "5. CLEAN OUTPUT: Return ONLY the raw SQL code. No explanation, no markdown blocks.\n\n"
        f"Question: {question}\n"
        "SQL Query:"
    )
    
    messages = [HumanMessage(content=system_prompt)]
    response = chat_model.invoke(messages)
    
    # Remove markdown formatting and whitespace
    sql = response.content.strip().replace("```sql", "").replace("```", "").split(';')[0].strip()
    
    # --- SECURITY LAYER 1: VALIDATION OF SQL COMMANDS ---
    forbidden_keywords = ["DROP", "DELETE", "INSERT", "UPDATE", "TRUNCATE", "ALTER", "CREATE", "GRANT", "REVOKE"]
    sql_upper = sql.upper()
    
    # Check if the response is actually a SQL query starting with SELECT
    if not sql_upper.startswith("SELECT"):
        raise Exception(f"AI Refused or Invalid Format: The model did not generate a safe SELECT query. Response: {sql}")
    
    # Check for forbidden keywords to prevent malicious injections
    for keyword in forbidden_keywords:
        if keyword in sql_upper:
            raise Exception(f"Security Violation: The keyword '{keyword}' is detected. Execution blocked.")
            
    return sql

# --- SESSION STATE FOR CHAT HISTORY ---
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display previous messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        if "df" in message:
            st.dataframe(message["df"])

# --- USER INPUT HANDLING ---
if prompt := st.chat_input("Ask about employees or salaries..."):
    # Add user message to history
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        try:
            with st.spinner("AI is thinking and verifying security..."):
                # 1. Generate and Filter SQL
                sql_query = generate_sql(prompt)
                
                # 2. Display SQL for the user (Audit Trail)
                st.code(sql_query, language="sql")
                
                # 3. Execute query
                result_raw = db.run(sql_query)
                
                # 4. Process and Display result
                if result_raw:
                    # Clean the result for Python evaluation
                    data = eval(str(result_raw))
                    if isinstance(data, list) and len(data) > 0:
                        df = pd.DataFrame(data)
                        st.dataframe(df, use_container_width=True)
                        st.success(f"Security Check Passed. Retrieved {len(df)} rows.")
                        
                        # Add assistant response to history
                        st.session_state.messages.append({
                            "role": "assistant", 
                            "content": "Result:", 
                            "df": df
                        })
                    else:
                        st.info("The query was successful, but no data matches your criteria.")
                else:
                    st.warning("Empty response from the database.")
        
        except Exception as e:
            # Enhanced Error Handling for UI
            error_msg = str(e)
            if "Security" in error_msg or "Unauthorized" in error_msg or "AI Refused" in error_msg:
                st.error(f"🚫 SECURITY ALERT: {error_msg}")
            else:
                st.error(f"❌ ERROR: {error_msg}")