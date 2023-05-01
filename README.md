### Introduction
This project extracts email addresses from the Google API and analyzes their digital footprint using machine learning techniques. 
The approach involves utilizing the haveibeenpwned API to obtain information about any data breaches associated with the domain name. 
The K-nearest neighbor clustering algorithm is used to classify the domain name based on their digital footprint and assess the risk level. 
A Flask application provides users with an intuitive user interface to view their digital footprint's details and take steps to protect their online privacy.

### Extension:
- OAuth: [Flask-OAuth](https://pythonhosted.org/Flask-OAuth/)
- Sqllite3: [Flask-Sqllite3](https://docs.python.org/3/library/sqlite3.html)
- Pickle: [Flask-Pickle]

## Installation

Install with pip:

```
$ pip install -r requirements.txt
```

## Flask Application Structure 
```
.
|──────app/
| |────__init__.py
| | |────cve/
| | |────user/
| | |────oauth/
| |──────config.Development.cfg
| |──────config.Production.cfg
| |──────config.Testing.cfg
| |────dao/
| |────model/
| |────oauth/
| |────util/
|──────run.py
|──────tests/

```


## Flask Configuration

#### Example

```
app = Flask(__name__)
app.config['DEBUG'] = True
```

#### Example Usage

```
app = Flask(__name__ )
app.config.from_pyfile('config.Development.cfg')
```


```

### OAuth Setup
add your `client_id` and `client_secret` into config file.



## Reference

Offical Website

- [Flask](http://flask.pocoo.org/)
- [Flask Extension](http://flask.pocoo.org/extensions/)
- [Flask-Sqllite3](https://flask.palletsprojects.com/en/2.2.x/patterns/sqlite3/)
- [Flask-OAuth](https://pythonhosted.org/Flask-OAuth/)

Tutorial

- [Flask Overview](https://www.slideshare.net/maxcnunes1/flask-python-16299282)
- [In Flask we trust](http://igordavydenko.com/talks/ua-pycon-2012.pdf)

[Wiki Page](https://github.com/tsungtwu/flask-example/wiki)



## Changelog

- Version 2.1 : add OAuth extension: FLASK-OAuth, and google oauth example
- Version 1.0 : add Sqllite3 extension
