from flask import Flask, render_template, url_for, request, redirect, flash, send_from_directory
from flask_login import LoginManager, login_user, UserMixin, login_required, current_user
from flask_jwt_extended import JWTManager, create_access_token
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
import json
import base64
from Crypto.Cipher import AES
import mysql.connector
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import secrets
from flask import request, jsonify
from flask_cors  import CORS, cross_origin 
import os  #tmb para chat
from werkzeug.utils import secure_filename
from datetime import timedelta
import re


app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type,Authorization'
app.secret_key = "secreto"
app.config['JWT_SECRET_KEY'] = 'la_mama_de_ira-hy'
jwt = JWTManager(app)

category_keywords = {
    1: ['producto', 'item', 'artículo'], #Productos
    3: ['visión', 'futuro', 'vision', 'vizion', 'vicion', 'future'], #Vision
    2: ['misión', 'propósito', 'mision', 'proposito', 'mizion', 'micion', 'propocito', 'propozito', 'mission'], #Mision
    4: ['historia', 'origen', 'istoria', 'history', 'iztoria', 'orijen' 'principio', 'prinsipio'], #Historia
    5: ['qué es', 'definición', 'que es', 'definicion', 'definision', 'def'], #Qué es
    6: ['qué hace', 'función', 'k ase', 'k asen', 'que hace', 'funsion'], #Qué hace
    7: ['servicios', 'asistencia', 'servisios, asistensia'] #Servicios
}
#categorizar
def categorize_question(pregunta):
    for category, keywords in category_keywords.items():
        for keyword in keywords:
            if re.search(r'\b' + re.escape(keyword) + r'\b', pregunta, re.IGNORECASE):
                return category
    return 'Uncategorized'

app.config['UPLOAD_FOLDER'] = 'static/uploads' #donde guardar 

login_manager = LoginManager(app)
login_manager.login_view = 'login'

key = 'sixteen_byte_key'

def conectar_sql():
    return mysql.connector.connect(user='admin', password='PuzzleSolutions',
                                    host='neoris-production.cloco8my8d90.us-east-2.rds.amazonaws.com',
                                    database='neoris')

def encrypt_password(password, key):
    key_bytes = key.encode('utf-8')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    # Por algun motivo esta parte es necesaria convertirla a bytes. Algo se SQL.
    password_bytes = password.encode('utf-8')
    fill_character_bytes = b' '
    # Que este de tamaño AES 16 bits
    padded_password = password_bytes.ljust(16, fill_character_bytes)
    encrypted_password = cipher.encrypt(padded_password)
    # Hexadecimal para aun mas sec.
    encrypted_hex = encrypted_password.hex()
    return encrypted_hex

class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password

#mas adelante servira
@login_manager.user_loader
def load_user(user_id):
    cnx = conectar_sql()
    cursor = cnx.cursor(dictionary=True)
    query = "SELECT * FROM user WHERE ID_user = %s"
    cursor.execute(query, (user_id,))
    user_data = cursor.fetchone()
    cursor.close()
    cnx.close()
    if user_data:
        return User(user_data['ID_user'], user_data['mail'], user_data['passW'])
    return None

@app.route('/')
@cross_origin()
@login_required 
def home():
    return render_template('home.html')

#YA FUNCIONA, solo esperando que se arregle lo del Auto Increment en BD.
@app.route('/register', methods=['GET','POST']) #HISTORIA 7.1  de inicio de sesión y registro#
@cross_origin()
def register():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        country = data.get('country')
        state = data.get('city')
        name = data.get('name')
        lastnameF = data.get('lastName')
        lastnameM = data.get('lastName')
        birthday = data.get('birthDate')
        gender = data.get('gender')
        userType = data.get('userType')
        password = data.get('password')
        
        # Encriptamos la contraseña
        encrypted_password = encrypt_password(password, key)
        
        # Guardamos en BD
        cnx = conectar_sql()
        cursor = cnx.cursor()
        query = "INSERT INTO user (mail, country, state, name, A_paterno, A_materno, birthday, gender, ID_userType, passW) VALUES (%s,  %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(query, (email, country, state, name, lastnameF, lastnameM, birthday, gender, userType, encrypted_password))
        cnx.commit()#
        cnx.commit()
        cursor.close()
        cnx.close()
        
        flash('Registration successful! You can now login.', 'success')
        return jsonify({'status': 1, 'message': 'Registration successful! You can now login.'}) #antes aqui se regresaba archivo html, ahora ya el JSON para lo que es la conexion propia. Mismo concepto en login :).
    #invalido !
    return jsonify({'status': 0, 'message': 'Invalid request'})

#aqui ya casi esta listo, solo espera de la bd correcta para ya tener la funcionalidad al cien
@app.route('/login', methods=['GET', 'POST']) #HISTORIA 7.1  de inicio de sesión y registro
@cross_origin()
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        #pido el id user para usarlo como identificador del jwt y eso sirve para los llamados posteriores
        password = data.get('password')
        if email and password:
            cnx = conectar_sql()
            cursor = cnx.cursor(dictionary=True)
            query = "SELECT * FROM user WHERE mail = %s"
            cursor.execute(query, (email,))
            user_data = cursor.fetchone()
            cursor.close()
            cnx.close()

            if user_data:
                # Comparamos
                encrypted_password = encrypt_password(password, key) #password unicamente sin el.utf
                print(encrypted_password) #debug
                print("BD: ", user_data['passW'])
                #Hay que convertirla a string porque la de DB es guardada en bytes, si no luego comparar no es posible
                db_password = user_data['passW'] # no es necesario decodificar porq ya es stirng (seguramente es algo de aws)
                # Es igual a la de la bd?
                if encrypted_password == db_password:  
                    user = User(user_data['ID_user'], user_data['mail'], user_data['passW']) #passW como en db
    
                    #esto lo hago para que solo se mande con el token el mail y el tipo de usuario y no la contraseña y otra info sensible
                    user_claims = {
                        'ID_user': user_data['ID_user'],
                        'mail': user_data['mail'],
                        'user_type': user_data['ID_userType']
                    }
                    expires_in = timedelta(days=1)  # Establece el tiempo de expiración a 7 días
                    access_token = create_access_token(identity=user_data['ID_user'], additional_claims=user_claims, expires_delta=expires_in)
                    login_user(user)
                    print("Entramos")
                    return jsonify({'status': 1, 'message': 'Login successful', 'access_token': access_token, 'user_type': user_data['ID_userType']})
                else:
                    print("incorrect")
                    return jsonify({'status': 0, 'message': 'Incorrect email or password'})
            else:
                return jsonify({'status': 0, 'message': 'User not found'})
        else:
             return jsonify({'status': 0, 'message': 'Email or password missing'})
    else:
        return jsonify({'status': 0, 'message': 'Invalid request'})
    
@app.route('/edit_user_data', methods=['PUT'])
@jwt_required()
@cross_origin()
def edit_user_data():
    if request.method == 'PUT':
        data = request.get_json()
        email = data.get('email')
        name = data.get('name')
        lastnameF = data.get('lastName')
        lastnameM = data.get('lastName')
        country = data.get('country')
        state = data.get('state')
        gender = data.get('gender')


        user_id = get_jwt_identity()
        
        # Guardamos en BD
        cnx = conectar_sql()
        cursor = cnx.cursor()
        query = "UPDATE user SET mail=  %s, country = %s,  state = %s, name = %s, A_paterno = %s, A_materno = %s, gender = %s WHERE ID_user = %s"
        cursor.execute(query, (email, country, state, name, lastnameF, lastnameM, gender, user_id))
        cnx.commit()
        cnx.commit()
        cursor.close()
        cnx.close()
        
        flash('Change successful!', 'success')
        return jsonify({'status': 1, 'message': 'Change successful!.'}) #antes aqui se regresaba archivo html, ahora ya el JSON para lo que es la conexion propia. Mismo concepto en login :).
    #invalido !
    return jsonify({'status': 0, 'message': 'Invalid request'})

def get_user_info(user_id):
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT * FROM user WHERE ID_user = %s"
        cursor.execute(query, (user_id,))
        user_info = cursor.fetchone()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return user_info
    except mysql.connector.Error as e:
        print("Error fetching user info:", e)
        return None

@app.route('/fetch_user_data', methods=['GET'])
@jwt_required()  # Requiere que la solicitud contenga un JWT válido
@cross_origin()
def get_user_by_jwt():
    try:
        # Obtiene la identidad del JWT, que debería ser el ID_user
        user_id_from_jwt = get_jwt_identity()
        print("User ID from JWT:", user_id_from_jwt)
        user_info = get_user_info(user_id_from_jwt)
        print(user_info)
        if user_info:
            return jsonify(user_info), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": "An error occurred"}), 500
    
@app.route('/access', methods=['GET'])
@jwt_required()
def is_admin():
    claims = get_jwt()
    return jsonify({'access':claims.get('user_type') }), 200

def get_user_type_info(user_id):
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT ID_userType FROM user WHERE ID_user = %s"
        cursor.execute(query, (user_id,))
        user_type = cursor.fetchone()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return user_type
    except mysql.connector.Error as e:
        print("Error fetching user info:", e)
        return None

@app.route('/fetch_user_type', methods=['GET'])
@jwt_required()  # Requiere que la solicitud contenga un JWT válido
@cross_origin()
def get_user_type_by_jwt():
    try:
        # Obtiene la identidad del JWT, que debería ser el ID_user
        user_id_from_jwt = get_jwt_identity()
        print("User ID from JWT:", user_id_from_jwt)
        user_type = get_user_type_info(user_id_from_jwt)
        print(user_type)
        if user_type:
            return jsonify(user_type), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": "An error occurred"}), 500
    

def get_faq_info():
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT * FROM preguntas WHERE ID_user IS NULL"
        #query = "CALL faqs();"
        cursor.execute(query)
        faq_info = cursor.fetchall()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return faq_info
    except mysql.connector.Error as e:
        print("Error fetching faq:", e)
        return None

@app.route('/fetch_faq', methods=['GET'])
@cross_origin()
def get_faq():
    faq = get_faq_info()
    if faq:
        return jsonify(faq), 200
    else:
        return jsonify({"error": "FAQ not found"}), 404
    
@app.route('/add_faq', methods=['POST'])
@cross_origin()
def add_faq():
    if request.method == 'POST':
        data = request.get_json()
        pregunta = data.get('pregunta')
        respuesta = data.get('respuesta')
        
        # Guardamos en BD
        cnx = conectar_sql()
        cursor = cnx.cursor()
        query = "INSERT INTO preguntas (pregunta, respuesta) VALUES (%s,  %s)"
        cursor.execute(query, (pregunta, respuesta))
        cnx.commit()
        cursor.close()
        cnx.close()
        
        flash('Addition successful!', 'success')
        return jsonify({'status': 1, 'message': 'Additon successful!'}) #antes aqui se regresaba archivo html, ahora ya el JSON para lo que es la conexion propia. Mismo concepto en login :).
    #invalido !
    return jsonify({'status': 0, 'message': 'Invalid request'})
    
@app.route('/edit_faq/<int:ID_preg>', methods=['PUT'])
@cross_origin()
def edit_faq(ID_preg):
    if request.method == 'PUT':
        data = request.get_json()
        pregunta = data.get('pregunta')
        respuesta = data.get('respuesta')
        
        # Guardamos en BD
        cnx = conectar_sql()
        cursor = cnx.cursor()
        query = "UPDATE preguntas SET pregunta=  %s, respuesta = %s WHERE ID_preg = %s"
        cursor.execute(query, (pregunta, respuesta,  ID_preg))
        cnx.commit()
        cnx.commit()
        cursor.close()
        cnx.close()
        
        flash('Change successful!', 'success')
        return jsonify({'status': 1, 'message': 'Change successful!.'}) #antes aqui se regresaba archivo html, ahora ya el JSON para lo que es la conexion propia. Mismo concepto en login :).
    #invalido !
    return jsonify({'status': 0, 'message': 'Invalid request'})

@app.route('/delete_faq/<int:ID_preg>', methods=['DELETE'])
@cross_origin()
def delete_faq(ID_preg):
    if request.method == 'DELETE':
        # Guardamos en BD
        cnx = conectar_sql()
        cursor = cnx.cursor()
        query = "DELETE FROM preguntas WHERE ID_preg = %s"
        cursor.execute(query, (ID_preg,))
        cnx.commit()
        cursor.close()
        cnx.close()
        
        flash('Delete successful!', 'success')
        return jsonify({'status': 1, 'message': 'Delete successful!.'}) #antes aqui se regresaba archivo html, ahora ya el JSON para lo que es la conexion propia. Mismo concepto en login :).
    #invalido !
    return jsonify({'status': 0, 'message': 'Invalid request'})


#Permitir archivos de fotos
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif', 'mp4'}

@app.route('/User', methods=['POST'])
@jwt_required()
@cross_origin()
def upload_image():
    try:
        if 'images' not in request.files:
            return jsonify({'status': 0, 'message': 'No file uploaded'}), 400

        files = request.files.getlist('images')
        user_id = get_jwt_identity()  # Obtener el ID del usuario autenticado

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # Actualiza la base de datos con el nuevo nombre de archivo
                cnx = conectar_sql()
                cursor = cnx.cursor()
                query = "UPDATE user SET filename = %s WHERE ID_user = %s"
                cursor.execute(query, (filename, user_id))
                cnx.commit()
                cursor.close()
                cnx.close()

        return jsonify({'status': 1, 'message': 'File(s) uploaded successfully'}), 200
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)}), 500


@app.route('/User/profile-pic', methods=['GET'])
@jwt_required()
def get_user_image():
    try:
        user_id = get_jwt_identity() # Obtén el ID del usuario actual
        cnx = conectar_sql()
        cursor = cnx.cursor()
        query = "SELECT filename FROM user WHERE ID_user = %s"
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        cursor.close()
        cnx.close()

        if result:
            filename = result[0]
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            if os.path.exists(file_path):
                return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
            else:
                return jsonify({'status': 0, 'message': 'Imagen no encontrada en el servidor'}), 404
        else:
            return jsonify({'status': 0, 'message': 'No tienes imagen..'}), 404
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)}), 500
    
def get_ps_info():
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT * FROM product_serv"
        cursor.execute(query)
        faq_info = cursor.fetchall()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return faq_info
    except mysql.connector.Error as e:
        print("Error fetching faq:", e)
        return None

@app.route('/fetch_ps', methods=['GET'])
@cross_origin()
def get_ps():
    faq = get_ps_info()
    if faq:
        return jsonify(faq), 200
    else:
        return jsonify({"error": "FAQ not found"}), 404
    
@app.route('/add_ps', methods=['POST'])
@cross_origin()
def add_ps():
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        descrip = data.get('descrip')
        print(data)
        
        # Guardamos en BD
        cnx = conectar_sql()
        cursor = cnx.cursor()
        query = "INSERT INTO product_serv (name, descrip) VALUES (%s,  %s)"
        cursor.execute(query, (name, descrip))
        cnx.commit()
        cnx.commit()
        cursor.close()
        cnx.close()
        
        flash('Addition successful!', 'success')
        return jsonify({'status': 1, 'message': 'Additon successful!'}) #antes aqui se regresaba archivo html, ahora ya el JSON para lo que es la conexion propia. Mismo concepto en login :).
    #invalido !
    return jsonify({'status': 0, 'message': 'Invalid request'})
    
@app.route('/edit_ps/<int:ID_ps>', methods=['PUT'])
@cross_origin()
def edit_ps(ID_ps):
    if request.method == 'PUT':
        data = request.get_json()
        name = data.get('name')
        descrip = data.get('descrip')
        
        
        # Guardamos en BD
        cnx = conectar_sql()
        cursor = cnx.cursor()
        query = "UPDATE product_serv SET name = %s, descrip = %s WHERE ID_ps = %s"
        cursor.execute(query, (name, descrip, ID_ps))
        cnx.commit()
        cnx.commit()
        cursor.close()
        cnx.close()
        
        flash('Change successful!', 'success')
        return jsonify({'status': 1, 'message': 'Change successful!.'}) #antes aqui se regresaba archivo html, ahora ya el JSON para lo que es la conexion propia. Mismo concepto en login :).
    #invalido !
    return jsonify({'status': 0, 'message': 'Invalid request'})

@app.route('/delete_ps/<int:ID_ps>', methods=['DELETE'])
@cross_origin()
def delete_ps(ID_ps):
    if request.method == 'DELETE':
        cnx = conectar_sql()
        cursor = cnx.cursor()
        query = "DELETE FROM product_serv WHERE ID_ps = %s"
        cursor.execute(query, (ID_ps,))
        cnx.commit()
        cnx.commit()
        cursor.close()
        cnx.close()
        
        flash('Delete successful!', 'success')
        return jsonify({'status': 1, 'message': 'Delete successful!.'}) #antes aqui se regresaba archivo html, ahora ya el JSON para lo que es la conexion propia. Mismo concepto en login :).
    #invalido !
    return jsonify({'status': 0, 'message': 'Invalid request'})

@app.route('/save_chat', methods=['POST'])
@cross_origin()
def save_chat():
    data = request.get_json()  # Obtener el JSON enviado
    print(data)  # Imprimir el JSON en la consola
    return jsonify({'status': 'success', 'message': 'Chat received', 'data': data}), 200

def get_messages_info(ID_user):
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT * FROM preguntas WHERE ID_user = %s "
        cursor.execute(query, (ID_user,))
        faq_info = cursor.fetchall()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return faq_info
    except mysql.connector.Error as e:
        print("Error fetching faq:", e)
        return None

@app.route('/fetch_messages', methods=['GET'])
@jwt_required()
@cross_origin()
def get_messages():
    ID_user = get_jwt_identity()
    messages = get_messages_info(ID_user)
    if messages:
        return jsonify(messages), 200
    else:
        return jsonify({"error": "Messages not found"}), 404
    
def get_all_messages_info():
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT * FROM preguntas "
        cursor.execute(query)
        faq_info = cursor.fetchall()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return faq_info
    except mysql.connector.Error as e:
        print("Error fetching faq:", e)
        return None

@app.route('/fetch_all_messages', methods=['GET'])
@cross_origin()
def get_all_messages():
    messages = get_all_messages_info()
    if messages:
        return jsonify(messages), 200
    else:
        return jsonify({"error": "Messages not found"}), 404
    
@app.route('/add_messages', methods=['POST'])
@jwt_required()
@cross_origin()
def add_messages():
    if request.method == 'POST':
        data = request.get_json()
        
        ID_user = get_jwt_identity()

        #Checa si es una lista
        if not isinstance(data, list):
            return jsonify({'status': 0, 'message': 'Invalid input, expected a list of messages'}), 400
        

        #Bulk create
        messages = []
        for message in data:
            pregunta = message.get('pregunta')
            respuesta = message.get('respuesta')
            time_date = message.get('time_date')
            #ID_faq = message.get('ID_faq')
            #segun la funcion de hasta arriba.

            if (pregunta == "" or pregunta == "0" or pregunta == "1" or pregunta == "2" or pregunta == "3" or pregunta == "4" or pregunta == "5"):
                category = 0
            else:
                category = categorize_question(pregunta.lower()) # PAra que no haya tema

            messages.append((pregunta, respuesta, time_date, category, ID_user))

        if not messages:
            return jsonify({'status': 0, 'message': 'No valid messages to insert'}), 400
        
        
        # Guardamos en BD
        cnx = conectar_sql()
        cursor = cnx.cursor()
        query = "INSERT INTO preguntas (pregunta, respuesta, time_date, ID_faq, ID_user) VALUES (%s,  %s, %s,  %s, %s)"
        cursor.executemany(query, messages)
        cnx.commit()
        cursor.close()
        cnx.close()
        
        flash('Addition successful!', 'success')
        return jsonify({'status': 1, 'message': 'Additon successful!'}) #antes aqui se regresaba archivo html, ahora ya el JSON para lo que es la conexion propia. Mismo concepto en login :).
    #invalido !
    return jsonify({'status': 0, 'message': 'Invalid request'})

@app.route('/add_interaction', methods=['POST'])
@jwt_required()
@cross_origin()
def add_interaction():
    if request.method == 'POST':
        data = request.get_json()

        rating = data.get('calificacion')
        duration = data.get('duracion')
        no_q = data.get('cantidadPreguntas')
        time_date = data.get('time_date')
        ID_user = get_jwt_identity()

        # Guardamos en BD
        cnx = conectar_sql()
        cursor = cnx.cursor()
        query = "INSERT INTO interaction (rating, duration, no_q, time_date, ID_user) VALUES (%s,  %s, %s,  %s, %s)"
        cursor.execute(query, (rating, duration, no_q, time_date, ID_user))
        cnx.commit()
        cursor.close()
        cnx.close()
        
        flash('Addition successful!', 'success')
        return jsonify({'status': 1, 'message': 'Additon successful!'}) #antes aqui se regresaba archivo html, ahora ya el JSON para lo que es la conexion propia. Mismo concepto en login :).
    #invalido !
    return jsonify({'status': 0, 'message': 'Invalid request'})

def get_interactions_info():
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT * FROM interaction"
        cursor.execute(query)
        faq_info = cursor.fetchall()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return faq_info
    except mysql.connector.Error as e:
        print("Error fetching interactions:", e)
        return None

@app.route('/fetch_interactions', methods=['GET'])
@cross_origin()
def get_interactions():
   
    interactions = get_interactions_info()
    if interactions:
        return jsonify(interactions), 200
    else:
        return jsonify({"error": "Messages not found"}), 404
    

def get_categories_info():
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT * FROM faq"
        cursor.execute(query)
        faq_info = cursor.fetchall()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return faq_info
    except mysql.connector.Error as e:
        print("Error fetching interactions:", e)
        return None

@app.route('/fetch_categories', methods=['GET'])
@cross_origin()
def get_categories():
   
    interactions = get_categories_info()
    if interactions:
        return jsonify(interactions), 200
    else:
        return jsonify({"error": "Messages not found"}), 404
    
def get_users_info():
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT * FROM user"
        #query = "CALL faqs();"
        cursor.execute(query)
        user_info = cursor.fetchall()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return user_info
    except mysql.connector.Error as e:
        print("Error fetching users:", e)
        return None

@app.route('/fetch_users', methods=['GET'])
@cross_origin()
def get_users():
    users = get_users_info()
    if users:
        return jsonify(users), 200
    else:
        return jsonify({"error": "FAQ not found"}), 404
    
def get_sat_stats_info():
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # SQL query to get satisfaction statistics
        query = """
        SELECT
            -- Employee (ID_userType = 2)
            (SELECT 
                JSON_OBJECT(
                    'Nulo', IFNULL(COUNT(CASE WHEN i.rating = 0 THEN 1 END), 0),
                    'Pobre', IFNULL(COUNT(CASE WHEN i.rating = 1 THEN 1 END), 0),
                    'Regular', IFNULL(COUNT(CASE WHEN i.rating = 2 THEN 1 END), 0),
                    'Buena', IFNULL(COUNT(CASE WHEN i.rating = 3 THEN 1 END), 0),
                    'MuyBuena', IFNULL(COUNT(CASE WHEN i.rating = 4 THEN 1 END), 0),
                    'Excelente', IFNULL(COUNT(CASE WHEN i.rating = 5 THEN 1 END), 0)
                )
            FROM interaction i
            JOIN user u ON i.ID_user = u.ID_user
            WHERE u.ID_userType = 2 AND i.ID_user IS NOT NULL) AS Empleados,

            -- Client (ID_userType = 3)
            (SELECT 
                JSON_OBJECT(
                    'Nulo', IFNULL(COUNT(CASE WHEN i.rating = 0 THEN 1 END), 0),
                    'Pobre', IFNULL(COUNT(CASE WHEN i.rating = 1 THEN 1 END), 0),
                    'Regular', IFNULL(COUNT(CASE WHEN i.rating = 2 THEN 1 END), 0),
                    'Buena', IFNULL(COUNT(CASE WHEN i.rating = 3 THEN 1 END), 0),
                    'MuyBuena', IFNULL(COUNT(CASE WHEN i.rating = 4 THEN 1 END), 0),
                    'Excelente', IFNULL(COUNT(CASE WHEN i.rating = 5 THEN 1 END), 0)
                )
            FROM interaction i
            JOIN user u ON i.ID_user = u.ID_user
            WHERE u.ID_userType = 3 AND i.ID_user IS NOT NULL) AS Clientes,

            -- Women (gender = 'Mujer')
            (SELECT 
                JSON_OBJECT(
                    'Nulo', IFNULL(COUNT(CASE WHEN i.rating = 0 THEN 1 END), 0),
                    'Pobre', IFNULL(COUNT(CASE WHEN i.rating = 1 THEN 1 END), 0),
                    'Regular', IFNULL(COUNT(CASE WHEN i.rating = 2 THEN 1 END), 0),
                    'Buena', IFNULL(COUNT(CASE WHEN i.rating = 3 THEN 1 END), 0),
                    'MuyBuena', IFNULL(COUNT(CASE WHEN i.rating = 4 THEN 1 END), 0),
                    'Excelente', IFNULL(COUNT(CASE WHEN i.rating = 5 THEN 1 END), 0)
                )
            FROM interaction i
            JOIN user u ON i.ID_user = u.ID_user
            WHERE u.gender = 'Mujer' AND i.ID_user IS NOT NULL) AS Mujeres,

            -- Men (gender = 'Hombre')
            (SELECT 
                JSON_OBJECT(
                    'Nulo', IFNULL(COUNT(CASE WHEN i.rating = 0 THEN 1 END), 0),
                    'Pobre', IFNULL(COUNT(CASE WHEN i.rating = 1 THEN 1 END), 0),
                    'Regular', IFNULL(COUNT(CASE WHEN i.rating = 2 THEN 1 END), 0),
                    'Buena', IFNULL(COUNT(CASE WHEN i.rating = 3 THEN 1 END), 0),
                    'MuyBuena', IFNULL(COUNT(CASE WHEN i.rating = 4 THEN 1 END), 0),
                    'Excelente', IFNULL(COUNT(CASE WHEN i.rating = 5 THEN 1 END), 0)
                )
            FROM interaction i
            JOIN user u ON i.ID_user = u.ID_user
            WHERE u.gender = 'Hombre' AND i.ID_user IS NOT NULL) AS Hombres,

            -- Others (gender not 'Female' or 'Male')
            (SELECT 
                JSON_OBJECT(
                    'Nulo', IFNULL(COUNT(CASE WHEN i.rating = 0 THEN 1 END), 0),
                    'Pobre', IFNULL(COUNT(CASE WHEN i.rating = 1 THEN 1 END), 0),
                    'Regular', IFNULL(COUNT(CASE WHEN i.rating = 2 THEN 1 END), 0),
                    'Buena', IFNULL(COUNT(CASE WHEN i.rating = 3 THEN 1 END), 0),
                    'MuyBuena', IFNULL(COUNT(CASE WHEN i.rating = 4 THEN 1 END), 0),
                    'Excelente', IFNULL(COUNT(CASE WHEN i.rating = 5 THEN 1 END), 0)
                )
            FROM interaction i
            JOIN user u ON i.ID_user = u.ID_user
            WHERE u.gender = 'Otros' AND i.ID_user IS NOT NULL) AS Otros,

            -- From Mexico (country = 'Mexico')
            (SELECT 
                JSON_OBJECT(
                    'Nulo', IFNULL(COUNT(CASE WHEN i.rating = 0 THEN 1 END), 0),
                    'Pobre', IFNULL(COUNT(CASE WHEN i.rating = 1 THEN 1 END), 0),
                    'Regular', IFNULL(COUNT(CASE WHEN i.rating = 2 THEN 1 END), 0),
                    'Buena', IFNULL(COUNT(CASE WHEN i.rating = 3 THEN 1 END), 0),
                    'MuyBuena', IFNULL(COUNT(CASE WHEN i.rating = 4 THEN 1 END), 0),
                    'Excelente', IFNULL(COUNT(CASE WHEN i.rating = 5 THEN 1 END), 0)
                )
            FROM interaction i
            JOIN user u ON i.ID_user = u.ID_user
            WHERE u.country = 'Mexico' AND i.ID_user IS NOT NULL) AS Mexico,

            -- From USA (country = 'USA')
            (SELECT 
                JSON_OBJECT(
                    'Nulo', IFNULL(COUNT(CASE WHEN i.rating = 0 THEN 1 END), 0),
                    'Pobre', IFNULL(COUNT(CASE WHEN i.rating = 1 THEN 1 END), 0),
                    'Regular', IFNULL(COUNT(CASE WHEN i.rating = 2 THEN 1 END), 0),
                    'Buena', IFNULL(COUNT(CASE WHEN i.rating = 3 THEN 1 END), 0),
                    'MuyBuena', IFNULL(COUNT(CASE WHEN i.rating = 4 THEN 1 END), 0),
                    'Excelente', IFNULL(COUNT(CASE WHEN i.rating = 5 THEN 1 END), 0)
                )
            FROM interaction i
            JOIN user u ON i.ID_user = u.ID_user
            WHERE u.country = 'Estados Unidos' AND i.ID_user IS NOT NULL) AS USA,

            -- General Rating
            (SELECT 
                JSON_OBJECT(
                    'Nulo', IFNULL(COUNT(CASE WHEN i.rating = 0 THEN 1 END), 0),
                    'Pobre', IFNULL(COUNT(CASE WHEN i.rating = 1 THEN 1 END), 0),
                    'Regular', IFNULL(COUNT(CASE WHEN i.rating = 2 THEN 1 END), 0),
                    'Buena', IFNULL(COUNT(CASE WHEN i.rating = 3 THEN 1 END), 0),
                    'MuyBuena', IFNULL(COUNT(CASE WHEN i.rating = 4 THEN 1 END), 0),
                    'Excelente', IFNULL(COUNT(CASE WHEN i.rating = 5 THEN 1 END), 0)
                )
            FROM interaction i
            WHERE i.ID_user IS NOT NULL) AS General;
        """
        # Execute the query
        cursor.execute(query)
        user_info = cursor.fetchone()  # Fetching only one row since we expect a single JSON object with all the ratings

        # Close cursor and connection
        cursor.close()
        cnx.close()

        # Parsing JSON strings to dictionaries
        user_info['Empleados'] = json.loads(user_info['Empleados'])
        user_info['Clientes'] = json.loads(user_info['Clientes'])
        user_info['Mujeres'] = json.loads(user_info['Mujeres'])
        user_info['Hombres'] = json.loads(user_info['Hombres'])
        user_info['Otros'] = json.loads(user_info['Otros'])
        user_info['Mexico'] = json.loads(user_info['Mexico'])
        user_info['USA'] = json.loads(user_info['USA'])
        user_info['General'] = json.loads(user_info['General'])

        return user_info
    except mysql.connector.Error as e:
        print("Error fetching users:", e)
        return None

@app.route('/fetch_sat_stats', methods=['GET'])
@cross_origin()
def get_sat_stats():
    sat_stats = get_sat_stats_info()
    if sat_stats:
        return jsonify(sat_stats), 200
    else:
        return jsonify({"error": "Messages not found"}), 404
    
def get_avg_time_info():
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT ROUND(AVG(duration), 2) AS timeSeconds FROM interaction  WHERE duration < 1000"
        #query = "CALL faqs();"
        cursor.execute(query)
        time_seconds = cursor.fetchone()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return time_seconds
    except mysql.connector.Error as e:
        print("Error fetching users:", e)
        return None

@app.route('/fetch_avg_time_interaction', methods=['GET'])
@cross_origin()
def get_avg_time():
    avg_time = get_avg_time_info()
    if avg_time:
        return jsonify(avg_time), 200
    else:
        return jsonify({"error": "FAQ not found"}), 404
    
def get_frequent_categories_info():
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT ID_faq, COUNT(*) AS question_count FROM preguntas WHERE ID_faq IS NOT NULL GROUP BY ID_faq ORDER BY question_count DESC LIMIT 5"
        #query = "CALL faqs();"
        cursor.execute(query)
        user_info = cursor.fetchall()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return user_info
    except mysql.connector.Error as e:
        print("Error fetching users:", e)
        return None

@app.route('/fetch_frequent_categories', methods=['GET'])
@cross_origin()
def get_frequent_categories():
    frequent_categories = get_frequent_categories_info()
    if frequent_categories:
        return jsonify(frequent_categories), 200
    else:
        return jsonify({"error": "FAQ not found"}), 404
    
def get_questions_count_info():
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT no_Q, COUNT(*) AS question_count FROM interaction WHERE no_Q IS NOT NULL GROUP BY no_Q ORDER BY no_Q ASC" 
        #query = "CALL faqs();"
        cursor.execute(query)
        user_info = cursor.fetchall()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return user_info
    except mysql.connector.Error as e:
        print("Error fetching users:", e)
        return None

@app.route('/fetch_questions_count', methods=['GET'])
@cross_origin()
def get_questions_count():
    questions_count = get_questions_count_info()
    if questions_count:
        return jsonify(questions_count), 200
    else:
        return jsonify({"error": "FAQ not found"}), 404
    
def get_questions_per_day_info():
    try:
        # Connect to the database
        cnx = conectar_sql()
        cursor = cnx.cursor(dictionary=True)

        # Execute the query to get user info
        query = "SELECT DATE_FORMAT(time_date, '%d %b %Y') AS day, SUM(no_Q) AS total_questions FROM interaction WHERE time_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 5 DAY) AND time_date IS NOT NULL GROUP BY DATE_FORMAT(time_date, '%d %b %Y') ORDER BY time_date DESC" 
        #query = "CALL faqs();"
        cursor.execute(query)
        user_info = cursor.fetchall()

        # Close cursor and connection
        cursor.close()
        cnx.close()

        return user_info
    except mysql.connector.Error as e:
        print("Error fetching questions per day:", e)
        return None

@app.route('/fetch_questions_per_day', methods=['GET'])
@cross_origin()
def get_questions_per_day():
    questions_per_day = get_questions_per_day_info()
    if questions_per_day:
        return jsonify(questions_per_day), 200
    else:
        return jsonify({"error": "Questions per day not found"}), 404

if __name__ == "__main__":
    app.run(debug=True, port=3001)