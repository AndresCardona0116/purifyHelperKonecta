<?php
namespace Konecta\PurifyHelper;

use Konecta\PurifyHelper\Helper\PurifyHelper;

class PurifyKsf 
{
    public function voidPurifyRequest($request,$arrExceptions){
        $response = [];
        if(!empty($request)){
            $objPurify = PurifyHelper::getInstance();
            $objPurify->setArrWhiteListInputs($arrExceptions);
            $response  = $objPurify->voidPurifyRequest($request);
        }
        return $response;
    }

}