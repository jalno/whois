<?php
namespace packages\whois;
class sc_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], array(), 'dmy');
        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic.sc',
            'registrar' => 'VCS (Pty) Limited'
        );
        return $r;
    }

}
