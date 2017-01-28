<?php
namespace packages\whois;
class info_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata']);
        $r['regyinfo'] = array(
            'referrer' => 'http://whois.afilias.info',
            'registrar' => 'Afilias Global Registry Services'
        );
        return $r;
    }

}
