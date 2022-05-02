<?php
namespace Konecta\PurifyHelper\Helper;
class PurifyHelper {
    private static $instance          = NULL;
    private $arrDataRequests          = []; #se almacenan datos que llegan en el request
    private $arrDataRequestsRecursion = []; #almacena los datos de los request que poseen arrays dentro
    private $recursion                = false; #le indica a los metodos con cual request trabajar
    private $arrPurifiedDataXSS       = []; #se almacenan datos purificados de XSS
    private $arrPossibleThreatsSql    = []; #se almacenan las posibles amenazas SQL
    private $arrPossibleThreatsXss    = []; #se almacenan las posibles amenazas XSS
    private $arrWhiteListInputs       = []; #se almacenan los inputs de los formularios que no pasan por las validaciones
    private $arrBlackListString       = [
                                            "/drop(\s)/i","/insert(\s)/i","/javascript(\s)/i","/script(\s)/i",
                                            "/alert(\s)/i","/select(\s)/i","/update(\s)/i", "/show(\s)/i",
                                            "/table(\s)/i","/create(\s)/i","/--/","/union(\s)/i",
                                            "/into(\s)/i","/\.\*/",
                                            "/((\"|')?[0-9](\"|')?(\s){0,})\=((\s){0,}(\"|')?[0-9](\"|')?(\s){0,})/"
                                        ];
    
    /**
     * @author KSF
     * @description -> metodo contructor privado para evitar creación de un nuevo
     * objecto
    **/ 
    private function __construct() {}


    /** 
     * @author KSF
     * @description -> metodo encargado de agregar valores al array de lista blanca,
     * con los inputs que no se desean pasar por la validación
     * @param array | null arrException
     * @return void
    **/
    public function setArrWhiteListInputs(array $arrException = []){
        $this->arrWhiteListInputs = $arrException;
    }

    /**
     * @author KSF
     * @description -> metodo para aplicar el patron
     * singleton
     * @return instance 
    **/ 
    public static function getInstance()
    {
        if (is_null(self::$instance)) {
            $class = __CLASS__;
            self::$instance = new $class;
        }
        return self::$instance;
    }                             

    /**
     * @author KSF
     * @description -> metodo principal del trait que recibe el request
     * de la petición para sanearlo de XSS y posible injection SQL
     * @param array $request
     * @return void 
    **/                                   
    public  function  voidPurifyRequest($request,$recursion = false){
        $response = array();
        try{
            $arrResponse = [];
            if(!empty($request)){
                if($recursion){
                    $this->arrDataRequestsRecursion = $request;
                    $this->recursion = true;
                }else{
                    $this->arrDataRequests = $request;
                }
                $this->voidPurifyXss();

                $this->voidPurifySqlInjection();
                if(!empty($this->arrPossibleThreatsSql) || !empty($this->arrPossibleThreatsXss)){
                    $arrResponse = [
                        'request'          => $this->arrDataRequests,
                        'requestXSS'       => $this->arrPossibleThreatsXss,
                        'requestInjection' => $this->simplifyPossibleThreat($this->arrPossibleThreatsSql)
                    ];                           
                    $response = array('valid' => false, 'response'=>$arrResponse);
                }else{
                    $response = array('valid' => true, 'response'=>[]);
                }
            } else{
                $response = array('valid' => true, 'response'=>[]);
            }
        }catch (\Throwable $th){
            $strMessage = 'Error en la linea ' . $th->getLine() . ' : ' . $th->getMessage();
            $response = array('valid' => false, 'response' => $strMessage);
        }
        return $response;
    }
    
    /**
     * @author KSF
     * @description -> metodo que procesa el request  verifica
     * por medio de la libreria Purify  la existencia de algun string relacionado con XSS
     * @param null
     * @return boolean 
    **/    
    private function voidPurifyXss(){
        $purify  = new \Stevebauman\Purify\Purify;
        $arrDataRequest = $this->evaluateRecursion();
        foreach($arrDataRequest as $arrDataRequestKey => $arrDataRequestValue){
            if(!in_array((string)$arrDataRequestKey,$this->arrWhiteListInputs)){
                if(is_array($arrDataRequestValue)){continue;}
                if(is_null($arrDataRequestValue)){ $arrDataRequestValue = ""; }
                if(is_int($arrDataRequestValue)){ $arrDataRequestValue = (string)$arrDataRequestValue.""; }
                if($arrDataRequestValue !== $purify->clean($arrDataRequestValue) && !is_numeric($arrDataRequestValue)){
                    $this->arrPossibleThreatsXss[$arrDataRequestKey][] = $arrDataRequestValue;
                }
                $this->arrPurifiedDataXSS[$arrDataRequestKey] = $purify->clean($arrDataRequestValue);
            }
        }
        return true;
    }

    /**
     * @author KSF
     * @description -> metodo que procesa el request y evalua
     * por medio de expresiones regulares la existencia de algun string relacionado con SQL
     * @param null
     * @return boolean 
    **/    
    private function voidPurifySqlInjection(){
        $arrDataRequest = $this->evaluateRecursion();
        foreach($arrDataRequest as $arrPurifiedDataKey => $arrPurifiedDataValue){
            if(!in_array($arrPurifiedDataKey, $this->arrWhiteListInputs)){
                foreach($this->arrBlackListString as $arrBlackListStringValue){
                    if(is_array($arrPurifiedDataValue) && !empty($arrPurifiedDataValue)){
                        if(isset($arrPurifiedDataValue['0'])){
                            $this->voidPurifyRequest($arrPurifiedDataValue['0'],true);
                            continue;
                        }else{
                            $this->voidPurifyRequest($arrPurifiedDataValue,true);
                            continue;
                        }
                    }
                    if(is_null($arrPurifiedDataValue) || !is_string($arrPurifiedDataValue)){continue;}
                    if(preg_match_all($arrBlackListStringValue, $arrPurifiedDataValue, $arrThreats)){
                         $this->arrPossibleThreatsSql[$arrPurifiedDataKey][] = $arrThreats;
                    }
                    $this->recursion = false;
                }
            }
        }
        return true;
    }


    /**
     * @author KSF
     * @description -> metodo simplifica la respusta de las expresiones regulares para su
     * facil utilización en el frontend
     * @param array -> array con posibles amenazas de SQL injection
     * @return array 
    **/  
    private function simplifyPossibleThreat(array $arrPossibleThreatsSql){
        $arrSimplified = [];
        foreach( $arrPossibleThreatsSql as $possibleThreatsKeyLevelOne => $possibleThreatsValueLevelOne){
            foreach($possibleThreatsValueLevelOne as  $possibleThreatsValueLevelTwo){
                foreach($possibleThreatsValueLevelTwo as $possibleThreatsValueLevelThree){

                    if(isset($possibleThreatsValueLevelThree['0']) && !empty(trim($possibleThreatsValueLevelThree['0']))){
                        $arrSimplified[$possibleThreatsKeyLevelOne][]=$possibleThreatsValueLevelThree['0'];
                    }
                }
            }
        }
        return $arrSimplified;
    }

    
    /**
     * @author KSF
     * @description -> metodo que evalua cual data debe ser iterada
     * @param  null
     * @return array 
    **/  
    private function evaluateRecursion(){
        return $this->recursion? $this->arrDataRequestsRecursion: $this->arrDataRequests;
    }

}