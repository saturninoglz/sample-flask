# ============================================
# Importaciones y configuración inicial
# ============================================

from flask import Flask, jsonify, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_cors import CORS
from datetime import timedelta
from sqlalchemy import Computed, Enum

# Inicialización de la aplicación Flask y configuración
app = Flask(__name__)
CORS(app)

# Configuración de la base de datos y JWT
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/axarquiasostenible'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(weeks=1)

# Inicialización de extensiones
db = SQLAlchemy(app)
jwt = JWTManager(app)

# ============================================
# Modelos de la base de datos
# ============================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def to_dict(self):
        return {col.name: getattr(self, col.name) for col in self.__table__.columns}

class Crop(db.Model):
    __tablename__ = 'crops'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # Ajustamos species y variety según el esquema (enums)
    species = db.Column(Enum('Aguacate', name='species_enum'), nullable=False)
    variety = db.Column(Enum('Hass', 'Pinkerton', name='variety_enum'))
    crop_name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer)
    row_spacing = db.Column(db.Integer)
    tree_spacing = db.Column(db.Integer)
    crop_area = db.Column(db.Float, nullable=False)
    plants_per_area = db.Column(db.Float)  # Campo generado por la BD
    irrigation_period_1 = db.Column(db.Float)
    irrigation_period_2 = db.Column(db.Float)
    irrigation_period_3 = db.Column(db.Float)

    def to_dict(self):
        # Devolver todos los campos, incluyendo los calculados
        return {col.name: getattr(self, col.name) for col in self.__table__.columns}

class CombinedWaterAnalysis(db.Model):
    __tablename__ = 'combined_water_analysis'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # AUTO_INCREMENT
    crop_id = db.Column(db.Integer, db.ForeignKey('crops.id'), nullable=False, unique=True)
    Amonio_NH4 = db.Column(db.Float, default=0)
    Nitrato_NO3 = db.Column(db.Float, default=0)
    Fosforo = db.Column(db.Float, default=0)
    Potasio = db.Column(db.Float, default=0)
    Calcio = db.Column(db.Float, default=0)
    Magnesio = db.Column(db.Float, default=0)
    Hierro = db.Column(db.Float, default=0)
    Zinc = db.Column(db.Float, default=0)
    Cobre = db.Column(db.Float, default=0)
    Manganeso = db.Column(db.Float, default=0)
    Boro = db.Column(db.Float, default=0)
    Nitrogeno_total = db.Column(db.Float)  # Generado por la BD
    Fosforo_ajustado = db.Column(db.Float) # Generado por la BD
    Potasio_ajustado = db.Column(db.Float) # Generado por la BD
    Calcio_ajustado = db.Column(db.Float)  # Generado por la BD
    Magnesio_ajustado = db.Column(db.Float) # Generado por la BD

    def to_dict(self):
        return {col.name: getattr(self, col.name) for col in self.__table__.columns}


class NutrientsGramsTreeWeekAvocado(db.Model):
    __tablename__ = 'nutrients_grams_tree_week_avocado'
    id = db.Column(db.Integer, primary_key=True)
    period = db.Column(db.Integer, nullable=False)
    Nitrogeno = db.Column(db.Float)
    Fosforo = db.Column(db.Float)
    Potasio = db.Column(db.Float)
    Calcio = db.Column(db.Float)
    Magnesio = db.Column(db.Float)
    Hierro = db.Column(db.Float)
    Zinc = db.Column(db.Float)
    Cobre = db.Column(db.Float)
    Manganeso = db.Column(db.Float)
    Boro = db.Column(db.Float)

    def to_dict(self):
        return {col.name: getattr(self, col.name) for col in self.__table__.columns}

# ============================================
# Endpoints de Autenticación
# ============================================

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            abort(400, description="Se requieren 'email' y 'password'.")

        email = data['email']
        password = data['password']

        # Verificar si el email ya está registrado
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "El correo electrónico ya está registrado."}), 400

        # Crear un nuevo usuario
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"msg": "Usuario registrado exitosamente."}), 201
    except Exception as e:
        print(e)
        return jsonify({"error": "Error interno del servidor."}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            abort(400, description="Se requieren 'email' y 'password'.")

        email = data['email']
        password = data['password']

        # Buscar al usuario por correo electrónico
        user = User.query.filter_by(email=email).first()

        if not user or user.password != password:
            # Verificar si el usuario existe y la contraseña es correcta
            return jsonify({"msg": "Correo electrónico o contraseña incorrectos"}), 401

        # Generar un token de acceso JWT con el ID del usuario como identidad
        access_token = create_access_token(identity=str(user.id))


        # Devolver el token en la respuesta
        return jsonify({"access_token": access_token, "user_id": user.id}), 200
    except Exception as e:
        print(f"Error durante el inicio de sesión: {e}")
        return jsonify({"error": "Error interno del servidor."}), 500

# ============================================
# Endpoints CRUD para Crop
# ============================================

# Crear un nuevo cultivo
@app.route('/api/crops', methods=['POST'])
@jwt_required()
def create_crop():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            abort(400, description="Se requieren los datos para crear un cultivo.")

        data['user_id'] = user_id
        # Crear el cultivo
        new_crop = Crop(**data)
        db.session.add(new_crop)
        db.session.commit()
        print(f"Cultivo creado con ID: {new_crop.id}")

        # Crear un análisis de agua asociado
        try:
            new_analysis = CombinedWaterAnalysis(
                crop_id=new_crop.id,
                Amonio_NH4=0,
                Nitrato_NO3=0,
                Fosforo=0,
                Potasio=0,
                Calcio=0,
                Magnesio=0,
                Hierro=0,
                Zinc=0,
                Cobre=0,
                Manganeso=0,
                Boro=0
            )
            db.session.add(new_analysis)
            db.session.commit()
            print(f"Análisis de agua creado para el cultivo con ID: {new_crop.id}")
        except Exception as analysis_error:
            print(f"Error al crear el análisis de agua: {analysis_error}")
            db.session.rollback()  # Revertir cambios del análisis si falla

        return jsonify(new_crop.to_dict()), 201
    except Exception as e:
        print(f"Error general al crear cultivo: {e}")
        db.session.rollback()  # Revertir cambios del cultivo si falla
        abort(500)


# Obtener todos los cultivos del usuario autenticado
@app.route('/api/crops', methods=['GET'])
@jwt_required()
def get_crops():
    try:
        user_id = get_jwt_identity()
        crops = Crop.query.filter_by(user_id=user_id).all()
        return jsonify([crop.to_dict() for crop in crops])
    except Exception as e:
        print(e)
        abort(500)


# Obtener un cultivo por ID (verifica que pertenezca al usuario autenticado)
@app.route('/api/crops/<int:id>', methods=['GET'])
@jwt_required()
def get_crop(id):
    try:
        user_id = get_jwt_identity()
        crop = Crop.query.filter_by(id=id, user_id=user_id).first_or_404()
        return jsonify(crop.to_dict())
    except Exception as e:
        print(e)
        abort(500)


# Actualizar un cultivo (verifica que pertenezca al usuario autenticado)
@app.route('/api/crops/<int:id>', methods=['PUT'])
@jwt_required()
def update_crop(id):
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        if not data:
            abort(400)
        
        crop = Crop.query.filter_by(id=id, user_id=user_id).first_or_404()

        for key, value in data.items():
            if hasattr(crop, key):
                setattr(crop, key, value)
        db.session.commit()
        return jsonify(crop.to_dict())
    except Exception as e:
        print(e)
        abort(500)


# Eliminar un cultivo (verifica que pertenezca al usuario autenticado)
@app.route('/api/crops/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_crop(id):
    try:
        user_id = get_jwt_identity()
        crop = Crop.query.filter_by(id=id, user_id=user_id).first_or_404()
        db.session.delete(crop)
        db.session.commit()
        return '', 204
    except Exception as e:
        print(e)
        abort(500)


# ============================================
# Endpoints CRUD para CombinedWaterAnalysis
# ============================================

@app.route('/api/combined_water_analysis', methods=['POST'])
@jwt_required()
def create_combined_water_analysis():
    try:
        data = request.get_json()
        if not data:
            abort(400, description="Se requieren los datos para crear un análisis de agua.")
        new_analysis = CombinedWaterAnalysis(**data)
        db.session.add(new_analysis)
        db.session.commit()
        return jsonify(new_analysis.to_dict()), 201
    except Exception as e:
        print(e)
        abort(500)

@app.route('/api/combined_water_analysis', methods=['GET'])
@jwt_required()
def get_combined_water_analyses():
    try:
        analyses = CombinedWaterAnalysis.query.all()
        return jsonify([analysis.to_dict() for analysis in analyses])
    except Exception as e:
        print(e)
        abort(500)

@app.route('/api/combined_water_analysis/<int:id>', methods=['GET'])
@jwt_required()
def get_combined_water_analysis(id):
    try:
        analysis = CombinedWaterAnalysis.query.get_or_404(id)
        return jsonify(analysis.to_dict())
    except Exception as e:
        print(e)
        abort(500)

@app.route('/api/combined_water_analysis/<int:id>', methods=['PUT'])
@jwt_required()
def update_combined_water_analysis(id):
    try:
        data = request.get_json()
        if not data:
            abort(400)
        analysis = CombinedWaterAnalysis.query.get_or_404(id)
        for key, value in data.items():
            if hasattr(analysis, key):
                setattr(analysis, key, value)
        db.session.commit()
        return jsonify(analysis.to_dict())
    except Exception as e:
        print(e)
        abort(500)

@app.route('/api/combined_water_analysis/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_combined_water_analysis(id):
    try:
        analysis = CombinedWaterAnalysis.query.get_or_404(id)
        db.session.delete(analysis)
        db.session.commit()
        return '', 204
    except Exception as e:
        print(e)
        abort(500)







@app.route('/api/combined_water_analysis/by_crop/<int:crop_id>', methods=['GET'])
@jwt_required()
def get_combined_water_analysis_by_crop(crop_id):
    try:
        analysis = CombinedWaterAnalysis.query.filter_by(crop_id=crop_id).first_or_404()
        return jsonify(analysis.to_dict())
    except Exception as e:
        print(e)
        abort(500)




@app.route('/api/combined_water_analysis/by_crop/<int:crop_id>', methods=['PUT'])
@jwt_required()
def update_combined_water_analysis_by_crop(crop_id):
    try:
        data = request.get_json()
        if not data:
            abort(400, description="Se requieren los datos para actualizar el análisis de agua.")

        # Buscar el análisis de agua asociado al crop_id
        analysis = CombinedWaterAnalysis.query.filter_by(crop_id=crop_id).first_or_404()

        # Actualizar los campos permitidos
        for key, value in data.items():
            if hasattr(analysis, key):
                setattr(analysis, key, value)

        db.session.commit()

        return jsonify(analysis.to_dict()), 200
    except Exception as e:
        print(e)
        abort(500)











# ============================================
# Endpoints CRUD para NutrientsGramsTreeWeekAvocado
# ============================================

@app.route('/api/nutrients', methods=['POST'])
@jwt_required()
def create_nutrient():
    try:
        data = request.get_json()
        if not data:
            abort(400, description="Se requieren los datos para crear un registro de nutrientes.")
        new_nutrient = NutrientsGramsTreeWeekAvocado(**data)
        db.session.add(new_nutrient)
        db.session.commit()
        return jsonify(new_nutrient.to_dict()), 201
    except Exception as e:
        print(e)
        abort(500)

@app.route('/api/nutrients', methods=['GET'])
@jwt_required()
def get_nutrients():
    try:
        nutrients = NutrientsGramsTreeWeekAvocado.query.all()
        return jsonify([nutrient.to_dict() for nutrient in nutrients])
    except Exception as e:
        print(e)
        abort(500)

@app.route('/api/nutrients/<int:id>', methods=['GET'])
@jwt_required()
def get_nutrient(id):
    try:
        nutrient = NutrientsGramsTreeWeekAvocado.query.get_or_404(id)
        return jsonify(nutrient.to_dict())
    except Exception as e:
        print(e)
        abort(500)

@app.route('/api/nutrients/<int:id>', methods=['PUT'])
@jwt_required()
def update_nutrient(id):
    try:
        data = request.get_json()
        if not data:
            abort(400)
        nutrient = NutrientsGramsTreeWeekAvocado.query.get_or_404(id)
        for key, value in data.items():
            if hasattr(nutrient, key):
                setattr(nutrient, key, value)
        db.session.commit()
        return jsonify(nutrient.to_dict())
    except Exception as e:
        print(e)
        abort(500)

@app.route('/api/nutrients/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_nutrient(id):
    try:
        nutrient = NutrientsGramsTreeWeekAvocado.query.get_or_404(id)
        db.session.delete(nutrient)
        db.session.commit()
        return '', 204
    except Exception as e:
        print(e)
        abort(500)

# ============================================
# Migración y ejecución
# ============================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

