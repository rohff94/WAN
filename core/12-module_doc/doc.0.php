<?php

/*
 * latex mydocument.tex
 * This will create "mydocument.dvi", a DVI document
 *
 * pdflatex mydocument.tex
 * This will generate "mydocument.pdf", a PDF document
 * latexmk -pdf mydocument.tex
 * 
 * https://ptestmethod.readthedocs.io/en/latest/LFF-IPS-P5-Reporting.html
 */



class DOC extends FILE{
	var $header_doc ;

	public function __construct($output_filepath_doc) {
		parent::__construct($output_filepath_doc);
		$this->header_doc = "<?php
    header(\"Content-type: application/vnd.ms-word\);
    header(\Content-Disposition: attachment; Filename=$output_filepath_doc\);?>";
		
			}



}


?>