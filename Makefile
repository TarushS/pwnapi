default:
	echo -e "\n\nUSAGE: make [install|update]\n"

install:
	python -m pip install -r requirements.txt --user
	python -m pip install -e . --user

sync:
	git pull origin master

update: sync install

clean:
	find . -name '*__pycache__' -exec rm -rf {} +
	find . -name '*.egg-info' -exec rm -rf {} +
	find . -name '.DS_Store' -delete
	find . -name '*.swp' -delete
	find . -name '*.pyc' -delete
	
upload:
	git add --all
	git commit
	git push origin master