# fwa - Furious Web scanner and Analyzer
A quick and easy web scanner and analyzer tool 

## How-To   
### Use against the owasp benchmark   
Copy the owasp sessions located in the `tests/owasp` folder in the `~/.fwa/sessions` folder: 
 ```  
cp tests/owasp/* ~/.fwa/sessions
 ```

## Development   
The source code is developed by using [poetry](https://python-poetry.org/) and [typer](https://typer.tiangolo.com/).   
To manage the CI flow, we  use [git flow](http://danielkummer.github.io/git-flow-cheatsheet/) to develop the software.   
### Create a new feature    

Features must be merged in the `develop` branch.
To start: 

1. Initialize:  
`git flow feature start analyzer-module`  

2. Commit the changes   
``` 
git add -A; git commit -am "<msg>"   
```  

3. Finish  
```  
git flow feature finish analyzer-module  
```   

### Create a new release   
A new release creates a release branch from the develop one.   
1. Update the version in the `pyproject.toml`   
2. Run `git flow release start <version>`  
3. Run `git flow release publish <release>`

