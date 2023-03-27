# fwa - Furious Web scanner and Analyzer
A quick and easy web scanner and analyzer tool 

## Run
You can see the usages with the `help` command: 
``` 
fwa --help 
``` 

### Development mode
In development mode, install deps with: `poetry install`, then use with `poetry run fwa`

### Record
Records a new session: 
```   
fwa records <session name>
``` 
it starts a proxy on `127.0.0.1:8080` 

### Replay 
To repeat the session: 
``` 
fwa replay <session name> 
``` 

### Fuzzing  
To fuzz a session: 
``` 
fwa fuzz <session name> 
```

## Examples

### Use against the owasp benchmark   
1. Run `fwa list` to initialize the project. 
2. Copy the owasp sessions located in the `tests/owasp` folder in the `~/.fwa/sessions` folder: 
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
