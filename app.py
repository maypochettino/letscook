import os
from collections import Counter
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
import sqlite3
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

import requests
import urllib.parse
from functools import wraps

import smtplib

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure  SQLite database
conexion = sqlite3.connect('recipes.db', check_same_thread=False)
db = conexion.cursor()

#login_required
def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method=="POST":

        #ingredient's list that input user
        ingredients = request.form.get('ingredients').split(", ")
        
        #ingredient's list of db
        data_nameIngredients = db.execute('SELECT name FROM ingredients').fetchall()
        nameIngredients = [i[0] for i in data_nameIngredients]
        
        #names of recipes that can cook with ingredients
        whatcook=[]
        for ingredient in ingredients:
            if ingredient.capitalize() not in nameIngredients:
                msg=f'Sorry. "{ingredient}" is not in ingredient list.'
                return render_template("index.html", message=msg)
            else:
                data_ingredient_ids = db.execute('SELECT id FROM ingredients WHERE name=?', [ingredient.capitalize()]).fetchall()
                ingredient_ids = [i[0] for i in data_ingredient_ids]

                prewhatcook=[]
                for i_id in ingredient_ids:
                    data_recipe_ids = db.execute('SELECT recipe_id FROM RecipeIngredients WHERE ingredient_id=?', [i_id]).fetchall()
                    recipe_ids = [id[0] for id in data_recipe_ids]

                    preprewhatcook=[]
                    for r_id in recipe_ids:
                        data_nameRecipe =  db.execute("SELECT name FROM recipes WHERE id=?", [r_id]).fetchall()
                        nameRecipe = [r[0] for r in data_nameRecipe]
                        preprewhatcook.append(nameRecipe[0])

                    prewhatcook.append(preprewhatcook[0])
                
                whatcook.append(prewhatcook[0])
        counted = Counter(whatcook)
        ordered = [value for value, count in counted.most_common()]

        #ids of recipes in ordered
        recipe_ids=[]
        for recipe_name in ordered:
            data_recipe_id = db.execute("SELECT id FROM recipes WHERE name=?", [recipe_name]).fetchall()
            recipe_id = [r[0] for r in data_recipe_id]
            recipe_ids.append(recipe_id[0])

        #recipe's list that could cook with ingredients and others
        resultRecipes = []
        for i in recipe_ids:

            data_amounts=db.execute("SELECT amount FROM RecipeIngredients WHERE recipe_id=?", [i]).fetchall()
            amounts=[a[0] for a in data_amounts]

            data_ingredient_ids=db.execute("SELECT ingredient_id FROM RecipeIngredients WHERE recipe_id=?", [i]).fetchall()
            ingredient_ids=[i[0] for i in data_ingredient_ids]

            data_measure_ids=db.execute("SELECT measure_id FROM RecipeIngredients WHERE recipe_id=?", [i]).fetchall()
            measure_ids=[a[0] for a in data_measure_ids]

            ingredientRecipe=[]
            measureRecipe=[]
            for x, y in zip(ingredient_ids, measure_ids):
                adding=db.execute("SELECT name FROM ingredients WHERE id=?", [x]).fetchone()
                ingredientRecipe.append(adding)
                addmeasure=db.execute("SELECT name FROM measures WHERE id=?", [y]).fetchone()
                measureRecipe.append(addmeasure)

            name=db.execute("SELECT name FROM recipes WHERE id=?", [i]).fetchone()
            instructions=db.execute("SELECT instructions FROM recipes WHERE id=?", [i]).fetchone()
            category=db.execute("SELECT category FROM recipes WHERE id=?", [i]).fetchone()

            resultRecipe={
                "name": name,
                "ingredients": ingredientRecipe,
                "amounts": amounts,
                "measures": measureRecipe,
                "instructions": instructions,
                "category": category
            }

            resultRecipes.append(resultRecipe)

        return render_template("whatcook.html", resultRecipes=resultRecipes)

    else:
        return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            msg="must provide username"
            return render_template("login.html", message=msg)

        # Ensure password was submitted
        elif not request.form.get("password"):
            msg="must provide password"
            return render_template("login.html", message=msg)


        # Query database for username
        username = request.form.get("username")
        db.execute("SELECT hash FROM users WHERE username = ?", [username] )
        pwhash = db.fetchone()

        # Ensure username exists and password is correct    
        if len(pwhash) != 1 or not check_password_hash(pwhash[0], request.form.get("password")):
            msg="invalid username and/or password"
            return render_template("login.html", message=msg)

        # Remember which user has logged in
        db.execute("SELECT id FROM users WHERE username = ?", [username] )
        ids = db.fetchall()
        session["user_id"] = ids[0]
        
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    #Register user
    if request.method == "POST":
        
        #username and email
        username = request.form.get("username")
        email=request.form.get("email")

        if not username:
            flash("Missing username")
            return render_template("register.html")
        data_usernames = db.execute('SELECT username FROM users')
        usernames = [i[0] for i in data_usernames]

        if not email:
            flash("must provide email")
            return render_template("register.html")
        data_emails = db.execute('SELECT email FROM users')
        emails = [i[0] for i in data_emails]

        if username in usernames:
            flash('Username already exists!')
            return render_template("register.html")

        if email in emails:
            flash("Email already exists")
            return render_template("register.html")

        #password
        password = request.form.get("password")
        if not password:
            flash("Missing password")
            return render_template("register.html")

        confirmation = request.form.get("confirmation")
        if not confirmation:
            flash("Missing confirmation")
            return render_template("register.html")

        if password != confirmation:
            flash("Passwords are different")
            return render_template("register.html")

        hash=generate_password_hash(password)
        db.execute("INSERT INTO users (username, email, hash) VALUES(?, ?, ?)", (username, email, hash))
        conexion.commit()

        #send email message HACER!!!!!!!!!
        FROM = "letscook"
        TO = email if isinstance(email, list) else [email]
        SUBJECT = f"Hello, {username}"
        TEXT = "Welcome to LETSCOOK!. You are registered successfully!"

        message = """From: %s\nTo: %s\nSubject: %s\n\n%s
        """ % (FROM, ", ".join(TO), SUBJECT, TEXT)
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.ehlo()
            server.starttls()
            server.login(os.environ.get("user_mail"), os.environ.get("user_pass"))
            server.sendmail(FROM, TO, message)
            server.close()
            print ('successfully sent the mail')
        except:
            print ("failed to send mail")

        return redirect("/")

    return render_template("register.html")


@app.route("/addrecipe", methods=["GET", "POST"])
@login_required
def addrecipe():
    message= None

    if request.method == 'POST':
        
        #input user
        name=request.form.get("name").capitalize()
        category=request.form.get("category").capitalize()
        instructions=request.form.get("instructions").capitalize()

        ingredient = request.form.getlist('ingredient[]')
        amount = request.form.getlist('amount[]')
        measure = request.form.getlist('measure[]')

        #complete all the fields
        if not name or not category or not instructions or not ingredient or not amount or not measure:
            message="Complete all the fields!"
            data_measures = db.execute('SELECT name FROM measures')
            measures = [m[0] for m in data_measures]
            return render_template("addrecipe.html", message=message, measures=measures)

        #save to tables
        data_namesRecipe = db.execute('SELECT name FROM recipes')
        namesRecipe = [nr[0] for nr in data_namesRecipe]
        if name in namesRecipe:
            message="Recipe's name already exist!"
            data_measures = db.execute('SELECT name FROM measures')
            measures = [m[0] for m in data_measures]
            return render_template("addrecipe.html", message=message, measures=measures)
        else:
            db.execute("INSERT INTO recipes(name, category, instructions) VALUES(?,?,?)", (name, category, instructions))
            conexion.commit()
            recipe_id = db.execute("SELECT id FROM recipes WHERE name=?", [name]).fetchone()


        data_ingredients = db.execute('SELECT name FROM ingredients')
        ingredients = [i[0] for i in data_ingredients]

        for i, a, m in zip(ingredient,amount,measure):

            if i not in ingredients:
                db.execute("INSERT INTO ingredients (name) VALUES (?)", [i.capitalize()])
                conexion.commit()

            ingredient_id=db.execute("SELECT id FROM ingredients WHERE name=?", [i.capitalize()]).fetchone()

            measure_id=db.execute("SELECT id FROM measures WHERE name=?", [m]).fetchone()

            db.execute("INSERT INTO RecipeIngredients(recipe_id, ingredient_id, measure_id, amount) VALUES (?, ?, ?, ?)", (recipe_id[0], ingredient_id[0], measure_id[0], a))
            conexion.commit()

        return redirect("/recipeslist")

    else:
        data_measures = db.execute('SELECT name FROM measures')
        measures = [m[0] for m in data_measures]
        return render_template("addrecipe.html", measures=measures)


@app.route("/recipeslist", methods=["GET", "POST"])
@login_required
def recipeslist():

    #search recipe from name
    if request.method == "POST":
        name=request.form.get("search").lower()
        print(name)

        data_recipe_ids = db.execute('SELECT id FROM recipes WHERE LOWER(name) LIKE (?) ', ["%"+name+"%"]).fetchall()
        recipe_ids = [id[0] for id in data_recipe_ids]
        print(recipe_ids)
        
        resultRecipes = []
        for i in recipe_ids:
            data_amounts=db.execute("SELECT amount FROM RecipeIngredients WHERE recipe_id=?", [i]).fetchall()
            amounts=[a[0] for a in data_amounts]

            data_ingredient_ids=db.execute("SELECT ingredient_id FROM RecipeIngredients WHERE recipe_id=?", [i]).fetchall()
            ingredient_ids=[i[0] for i in data_ingredient_ids]

            data_measure_ids=db.execute("SELECT measure_id FROM RecipeIngredients WHERE recipe_id=?", [i]).fetchall()
            measure_ids=[a[0] for a in data_measure_ids]

            ingredientRecipe=[]
            measureRecipe=[]
            for x, y in zip(ingredient_ids, measure_ids):
                adding=db.execute("SELECT name FROM ingredients WHERE id=?", [x]).fetchone()
                ingredientRecipe.append(adding)
                addmeasure=db.execute("SELECT name FROM measures WHERE id=?", [y]).fetchone()
                measureRecipe.append(addmeasure)

            name=db.execute("SELECT name FROM recipes WHERE id=?", [i]).fetchone()
            instructions=db.execute("SELECT instructions FROM recipes WHERE id=?", [i]).fetchone()
            category=db.execute("SELECT category FROM recipes WHERE id=?", [i]).fetchone()

            resultRecipe={
                "name": name,
                "ingredients": ingredientRecipe,
                "amounts": amounts,
                "measures": measureRecipe,
                "instructions": instructions,
                "category": category
                }

            resultRecipes.append(resultRecipe)
        return render_template("search.html", resultRecipes=resultRecipes)
    else:

        #select ids of recipes order by name
        data_recipe_ids = db.execute('SELECT id FROM recipes ORDER BY UPPER(name)').fetchall()
        recipe_ids = [id[0] for id in data_recipe_ids]
        print(recipe_ids)

        #create tables of recipes with all the items
        resultRecipes = []
        for i in recipe_ids:
            data_amounts = db.execute('SELECT amount FROM RecipeIngredients WHERE recipe_id=?', [i])
            amounts = [a[0] for a in data_amounts]
            
            data_ingredient_ids = db.execute('SELECT ingredient_id FROM RecipeIngredients WHERE recipe_id=?', [i])
            ingredient_ids = [i[0] for i in data_ingredient_ids]
            
            data_measure_ids = db.execute('SELECT measure_id FROM RecipeIngredients WHERE recipe_id=?', [i])
            measure_ids = [m[0] for m in data_measure_ids]

            ingredientRecipe=[]
            measureRecipe=[]
            for x, y in zip(ingredient_ids, measure_ids):
                adding=db.execute("SELECT name FROM ingredients WHERE id=?", [x]).fetchone()
                ingredientRecipe.append(adding)
                addmeasure=db.execute("SELECT name FROM measures WHERE id=?", [y]).fetchone()
                measureRecipe.append(addmeasure)

            name=db.execute("SELECT name FROM recipes WHERE id=?", [i]).fetchone()
            instructions=db.execute("SELECT instructions FROM recipes WHERE id=?", [i]).fetchone()
            category=db.execute("SELECT category FROM recipes WHERE id=?", [i]).fetchone()

            resultRecipe={
                "name": name,
                "ingredients": ingredientRecipe,
                "amounts": amounts,
                "measures": measureRecipe,
                "instructions": instructions,
                "category": category
            }

            resultRecipes.append(resultRecipe)

        return render_template("recipeslist.html", resultRecipes=resultRecipes)