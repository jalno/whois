<?php
namespace packages\whois;
class pro_handler {

    function parse($data, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data['rawdata']);
        $r['regyinfo']['referrer'] = 'http://www.registrypro.pro';
        $r['regyinfo']['registrar'] = 'RegistryPRO';
        return $r;
    }

}
