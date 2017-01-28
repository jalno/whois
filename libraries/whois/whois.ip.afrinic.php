<?php
namespace packages\whois;
class afrinic_handler {

    function parse($data_str, $query) {
        $translate = array(
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl' => 'handle',
            'person' => 'name',
            'netname' => 'name',
            'organisation' => 'handle',
            'org-name' => 'organization',
            'org-type' => 'type'
        );

        $contacts = array(
            'admin-c' => 'admin',
            'tech-c' => 'tech',
            'org' => 'owner'
        );

        $r = generic_parser_a($data_str, $translate, $contacts, 'network', 'Ymd');

        if (isset($r['network']['descr'])) {
            $r['owner']['organization'] = $r['network']['descr'];
            unset($r['network']['descr']);
        }

        if (isset($r['owner']['remarks']) && is_array($r['owner']['remarks']))
            while (list($key, $val) = each($r['owner']['remarks'])) {
                $pos = strpos($val, 'rwhois://');

                if ($pos !== false)
                    $r['rwhois'] = strtok(substr($val, $pos), ' ');
            }

        $r = array('regrinfo' => $r);
        $r['regyinfo']['type'] = 'ip';
        $r['regyinfo']['registrar'] = 'African Network Information Center';
        return $r;
    }

}
