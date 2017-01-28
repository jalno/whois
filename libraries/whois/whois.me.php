<?php
namespace packages\whois;
class me_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata']);
        $r['regyinfo'] = array(
            'referrer' => 'http://domain.me',
            'registrar' => 'doMEn'
        );
        return $r;
    }

}
