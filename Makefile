pdf: eotp.pdf 
eotp.pdf : eotp.tex eotp.bib
	pdflatex eotp.tex
	bibtex eotp
	pdflatex eotp.tex
	pdflatex eotp.tex

clean:
	rm *.class eotp.log eotp.aux map.out

