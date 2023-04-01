# how to set up and use kickabout

## setup

* git clone git@github.com:McPeball/kickabout.git
* python -m venv venv
* source venv/bin/activate
* conda install -c anaconda flask
* pip install flask 
* export FLASK_APP=app.py
* export FLASK_ENV=development
* flask run

The commands above setup the environment to run the flask kickabout app.

For convenience, the export and flask run commands are contained in `run.sh`.

## Description of resources

* app.py
	- main functions to run kickabout app
	- doc strings explain arguments and return values of each function
* /templates
	 - jinga html templates
* /static/images
	 - images of example plots
