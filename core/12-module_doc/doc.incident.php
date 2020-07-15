<?php
/*
 * Which of the following correctly lists the six steps of incident handling in the correct sequence?
 * Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned


 The scope of incident handling is greater than just intrusions; it covers insider crime and intentional and unintentional events that cause a loss of availability. 
Furthermore, intellectual property is becoming more important as we move into an information age. 
Types of intellectual property include brands, proprietary information, trade secrets, patents, copyrights, and trademarks
The best way to act on an incident and minimize your chance of a mistake is by having proper
procedures in place. Well-documented procedures ensure that yoti know what to do when an incident occurs and
minimize the chances that you will forget something.


Preparation, Identification, Containment, Eradication, Recovery, and Lessons Learned


Incident Response Forensic Framework :
https://github.com/biggiesmallsAG/nightHawkResponse

 */

class INCIDENT_DOC extends DOC{
	var $template_ChainOfCustody;
	var $template_IH_CommunicationLog;
	var $template_IH_Contacts;
	var $template_IH_Containment;
	var $template_IH_Eradication;
	var $template_IH_Identification;
	var $template_IH_Survey;
	var $template_IPIH_CommunicationLog;
	var $template_IPIH_Contacts;
	var $template_IPIH_Containment;
	var $template_IPIH_Eradication;
	var $template_IPIH_FormChecklist;
	var $template_IPIH_Identification;
	var $template_NIST_SP_800_61r2;
	
	

	public function __construct($output_filepath_doc_incident) {
		parent::__construct($output_filepath_doc_incident);
		
		$this->template_ChainOfCustody =<<<FIN
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=Windows-1252" />
</head>
<body>
<table border="1">
    <tr>
        <td bgcolor="#137799" colspan="4" ><center><strong>EVIDENCE / PROPERTY CHAIN OF CUSTODY</strong></center></td>
    </tr>
    <tr valign="top">
    <td><center><strong>REFERENCE NO.</strong></center><br />%%REFERENCE%%<br /> </td>
 	<td colspan="3" ><center><strong>DESCRIPTION</strong></center><br />%%DESCRIPTION%%<br /></td>
    </tr>
    <tr valign="top">
        <td ><strong><center>ITEM NO.</strong></center></br><br /><br /></br></br><br /><br /></br></br><br /><br /></br></br><br /><br /></br></br></br><br /><br /></br><br /></br></br><br /><br /></br></br><br /><br /></br></td>
        <td><strong><center>QUANTITY</strong></center></td>
        <td colspan="2" ><center><strong>DESCRIPTION OF ARTICLES (If physical device, include manufacturer, model, and serial number</strong>)</center></td>
    </tr>
    <tr  valign="top">
        <td><strong>Date Time</strong><br /><br /><br /><br /></td>
        <td><strong>FROM</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>TO</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>PURPOSE OF CHANGE OF CUSTODY</strong><br /><br /><br /><br /></td>
    </tr>
     <tr  valign="top">
        <td><strong>Date Time</strong><br /><br /><br /><br /></td>
        <td><strong>FROM</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>TO</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>PURPOSE OF CHANGE OF CUSTODY</strong><br /><br /><br /><br /></td>
    </tr>
    <tr  valign="top">
        <td><strong>Date Time</strong><br /><br /><br /><br /></td>
        <td><strong>FROM</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>TO</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>PURPOSE OF CHANGE OF CUSTODY</strong><br /><br /><br /><br /></td>
    </tr>
        <tr  valign="top">
        <td><strong>Date Time</strong><br /><br /><br /><br /></td>
        <td><strong>FROM</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>TO</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>PURPOSE OF CHANGE OF CUSTODY</strong><br /><br /><br /><br /></td>
    </tr>
        <tr  valign="top">
        <td><strong>Date Time</strong><br /><br /><br /><br /></td>
        <td><strong>FROM</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>TO</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>PURPOSE OF CHANGE OF CUSTODY</strong><br /><br /><br /><br /></td>
    </tr>
        <tr  valign="top">
        <td><strong>Date Time</strong><br /><br /><br /><br /></td>
        <td><strong>FROM</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>TO</strong><br /><br /><br /><br /></td>
        Name :</br><br /><br /></br>
        ORGANISATION :</br><br /><br /></br>
        SIGNATURE :</br><br /><br /></br>
        <td><strong>PURPOSE OF CHANGE OF CUSTODY</strong><br /><br /><br /><br /></td>
    </tr>
</table>
</body>
</html>
FIN;
		
	}
	
	
	public function incident_ChainOfCustody(){
		$this->ssTitre(__FUNCTION__);
		
	}
	
	
	public function incident_IH_CommunicationLog(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_IH_Contacts(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_IH_Containment(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_IH_Eradication(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_IH_Identification(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_IH_Survey(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_IPIH_CommunicationLog(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_IPIH_Contacts(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_IPIH_Containment(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_IPIH_Eradication(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_IPIH_FormChecklist(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_IPIH_Identification(){
		$this->ssTitre(__FUNCTION__);
		
	}
	public function incident_NIST_SP_800_61r2(){
		$this->ssTitre(__FUNCTION__);
		
	}
	
	
}