from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

from model_logic import SafeSpectAI

app = Flask(__name__)
app.secret_key = 'safespect_secret_key' # Needed for sessions/flash messages



# Load the AI Engine once when the server starts
# Ensure 'models/ids_model.pkl' exists in your folder
ai_engine = SafeSpectAI('models/ids_model.pkl')

# Mock User Database
users = {
    "admin@safespect.ai": "password123"
}

@app.route('/')
def index():
    if 'user_email' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', user_email=session['user_email'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if email in users and users[email] == password:
            session['user_email'] = email
            return redirect(url_for('index'))
        else:
            flash("Invalid email or password", "error")
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        # Logic to save user to DB would go here
        users[email] = password 
        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('login'))
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    
    # Pre-process: Convert strings from form to floats/ints for the model
    processed_data = {k: float(v) for k, v in data.items()}
    
    # Run the AI logic
    results = ai_engine.predict_and_explain(processed_data)
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)