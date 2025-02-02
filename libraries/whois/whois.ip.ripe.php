<?php
namespace packages\whois;
class ripe_handler {

    function parse($data_str, $query) {
        $translate = array(
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl' => 'handle',
            'person' => 'name',
            'netname' => 'name',
            'descr' => 'desc'
        );

        $contacts = array(
            'admin-c' => 'admin',
            'tech-c' => 'tech'
        );

        if (!empty($data_str['rawdata']))
            $data_str = $data_str['rawdata'];

        $r = generic_parser_a($data_str, $translate, $contacts, 'network');

        if (isset($r['network']['desc'])) {
            $r['owner']['organization'] = $r['network']['desc'];
            unset($r['network']['desc']);
        }

        if (isset($r['admin']['abuse-mailbox'])) {
            $r['abuse']['email'] = $r['admin']['abuse-mailbox'];
            unset($r['admin']['abuse-mailbox']);
        }

        if (isset($r['tech']['abuse-mailbox'])) {
            $r['abuse']['email'] = $r['tech']['abuse-mailbox'];
            unset($r['tech']['abuse-mailbox']);
        }

        // Clean mess
        if (isset($r['tech']['tech-c']))
            unset($r['tech']['tech-c']);
        if (isset($r['tech']['admin-c']))
            unset($r['tech']['admin-c']);
        if (isset($r['admin']['tech-c']))
            unset($r['admin']['tech-c']);
        if (isset($r['admin']['admin-c']))
            unset($r['admin']['admin-c']);

        $r = array('regrinfo' => $r);
        $r['regyinfo']['type'] = 'ip';
        $r['regyinfo']['registrar'] = 'RIPE Network Coordination Centre';
        return $r;
    }

}
