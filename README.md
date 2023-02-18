# fwa - Furious Web scanner and Analyzer
A quick and easy web scanner and analyzer tool 



## Development   
The source code is developed by using [poetry](https://python-poetry.org/) and [typer](https://typer.tiangolo.com/).   
To manage the CI flow, we  use [git flow](http://danielkummer.github.io/git-flow-cheatsheet/) to develop the software.   
### Create a new feature  

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

