<?php
namespace packages\whois;
class museum_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata']);
        $r['regyinfo'] = array(
            'referrer' => 'http://musedoma.museum',
            'registrar' => 'Museum Domain Management Association'
        );
        return $r;
    }

}
