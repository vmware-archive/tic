from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file, get_sample_details
from django.template.loader import render_to_string
from . import forms

import cbapi
import csv
import cStringIO as StringIO
import json
import ntpath
import os
import requests
import time
import zipfile
import traceback

class CarbonBlackService(Service):
    name = "Carbon Black"
    version = "1.0.0"
    supported_types = ['Sample', 'IP', 'Domain']
    description = "Retrieve process results of a binary from a Carbon Black Server"

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.CarbonBlackInegrationConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def parse_config(config):
        if not config['cb_server_url']:
            raise ServiceConfigError('Carbon Black Server URL required.')
        if not config['cb_api_token']:
            raise ServiceConfigError("Carbon Black API Token required.")
        #if not config['cb_crits_user']:
        #    raise ServiceConfigError("Username for Carbon Black Service.")

    @staticmethod
    def get_config_details(config):
        display_config = {}
        # Rename keys so they render nice.
        fields = forms.CarbonBlackInegrationConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.CarbonBlackInegrationConfigForm(initial=config),
                                 'config_error': None})
        form = forms.CarbonBlackInegrationConfigForm
        return form, html

    def run(self, obj, config):
        self.obj = obj
        self.config = config
        self.completed_uids = []
        if obj._meta['crits_type'] == 'Sample':
            self.get_carbonblack_sample_data()

        elif obj._meta['crits_type'] == 'IP':
            self.get_carbonblack_ip_data()

        elif obj._meta['crits_type'] == 'Domain':
            self.get_carbonblack_domain_data()

    def get_carbonblack_sample_data(self):
        CB_URL = self.config['cb_server_url']
        CB_TOKEN = self.config['cb_api_token']
        #CB_CRITS_USER = self.config['cb_crits_user']
        CB_SSL_VERIFY = False

        self._info('Attempting to connect to %s' % CB_URL)
        cb = cbapi.CbApi(CB_URL, token=CB_TOKEN, ssl_verify=CB_SSL_VERIFY)
        process_results = {}

        found_results = False
        initial_wait_time = self.config.get('cb_initial_wait_time')
        if initial_wait_time > 0:
            self._info('Sleeping an initial %d seconds' % initial_wait_time)
            time.sleep(initial_wait_time)

        time_waiting = 0
        max_wait_time = self.config.get('cb_max_wait_time')
        while not found_results:
            process_results = cb.process_search('process_md5:%s' % self.obj.md5)
            if process_results['total_results'] != 0:
                found_results = True
                self._info("Results found")
            else:
                time.sleep(10) 
                time_waiting += 10
                self._info("No results found, sleeping for 10 seconds")
                if time_waiting > max_wait_time:
                    self._info("Timeout hit")
                    break

        for result in process_results['results']:
            data = {}
            data['start time'] = result['start']
            data['hostname'] = result['hostname']
            data['username'] = result['username']
            data['pid'] = result['process_pid']
            data['ModLoad Count'] = result['modload_count']
            data['FileMod Count'] = result['filemod_count']
            data['RegMod Count'] = result['regmod_count']
            data['NetConn Count'] = result['netconn_count']
            data['ChildProc Count'] = result['childproc_count']
            data['CrossProc Count'] = result['crossproc_count']

            self._add_result('Processes Found', result['process_name'], data)


        for result in process_results['results']:
            pid = result['process_pid']
            hostname = result['hostname']

            if result['id'] not in self.completed_uids:
                self.completed_uids.append(result['id'])
            else:
                continue
            report = cb.process_report(result['id'], result['segment_id'])
            report_io = StringIO.StringIO(report)
            zfo = zipfile.ZipFile(report_io)

            self.show_modloads(zfo, 'Module loads for ' + hostname + '/' + str(pid))
            self.show_filemods(zfo, 'File Modifications for ' + hostname + '/' + str(pid))
            self.show_regmods(zfo, 'Registry Modifications for ' + hostname + '/' + str(pid))
            self.show_netconns(zfo, 'Network Connections for ' + hostname + '/' + str(pid))
            self.show_childprocs(zfo, cb, 'Child Processes for ' + hostname + '/' + str(pid), hostname, pid)

    def get_carbonblack_ip_data(self):
        CB_URL = self.config['cb_server_url']
        CB_TOKEN = self.config['cb_api_token']
        CB_SSL_VERIFY = False
        self._info('Attempting to connect to %s' % CB_URL)
        cb = cbapi.CbApi(CB_URL, token=CB_TOKEN, ssl_verify=CB_SSL_VERIFY)
        process_results = cb.process_search('ipaddr:%s' % self.obj.ip)

        proc_count = len(process_results['results'])
        proc_string = '1 Process Found'
        if proc_count > 1:
            proc_string = "%d Processes Found" % proc_count

        for result in process_results['results']:
            data = {}
            data['start time'] = result['start']
            data['hostname'] = result['hostname']
            data['username'] = result['username']
            data['name'] = result['process_name']
            data['pid'] = result['process_pid']

            self._add_result(proc_string, result['process_md5'], data)

        for result in process_results['results']:
            pid = result['process_pid']
            hostname = result['hostname']

            report = cb.process_report(result['id'], result['segment_id'])
            report_io = StringIO.StringIO(report)
            zfo = zipfile.ZipFile(report_io)
            netconn_obj = zfo.open('csv/netconn.csv')
            netconn_data = netconn_obj.read()
            netconn_obj.close()
            netconn_io = StringIO.StringIO(netconn_data)
            netconn_csv = csv.reader(netconn_io)
            try:
                while 1:
                    netconns = netconn_csv.next()
                    nc = {}
                    IP = netconns[1]
                    if IP != self.obj.ip:
                        continue
                    nc['Timestamp'] = netconns[0]
                    nc['Domain'] = netconns[4]
                    nc['Port'] = netconns[2]
                    nc['Protocol'] = netconns[3]
                    nc['Direction'] = netconns[5]
                    self._add_result('Network Connections to %s' % self.obj.ip, IP, nc)
            except StopIteration as si:
                pass
            except Exception as e:
                self._info(traceback.format_exc())

    def get_carbonblack_domain_data(self):
        CB_URL = self.config['cb_server_url']
        CB_TOKEN = self.config['cb_api_token']
        CB_SSL_VERIFY = False
        self._info('Attempting to connect to %s' % CB_URL)
        cb = cbapi.CbApi(CB_URL, token=CB_TOKEN, ssl_verify=CB_SSL_VERIFY)
        process_results = cb.process_search('domain:%s' % self.obj.domain)

        proc_count = len(process_results['results'])
        proc_string = '1 Process Found'
        if proc_count > 1:
            proc_string = "%d Processes Found" % proc_count

        for result in process_results['results']:
            data = {}
            data['start time'] = result['start']
            data['hostname'] = result['hostname']
            data['username'] = result['username']
            data['name'] = result['process_name']
            data['pid'] = result['process_pid']

            self._add_result(proc_string, result['process_md5'], data)

        for result in process_results['results']:
            pid = result['process_pid']
            hostname = result['hostname']

            report = cb.process_report(result['id'], result['segment_id'])
            report_io = StringIO.StringIO(report)
            zfo = zipfile.ZipFile(report_io)
            netconn_obj = zfo.open('csv/netconn.csv')
            netconn_data = netconn_obj.read()
            netconn_obj.close()
            netconn_io = StringIO.StringIO(netconn_data)
            netconn_csv = csv.reader(netconn_io)
            try:
                while 1:
                    netconns = netconn_csv.next()
                    nc = {}
                    domain = netconns[4]
                    if domain != self.obj.domain:
                        continue
                    nc['Timestamp'] = netconns[0]
                    nc['IP'] = netconns[1]
                    nc['Port'] = netconns[2]
                    nc['Protocol'] = netconns[3]
                    nc['Direction'] = netconns[5]
                    self._add_result('Network Connections to %s' % self.obj.domain, domain, nc)
            except StopIteration as si:
                pass
            except Exception as e:
                self._info(traceback.format_exc())


    def show_modloads(self, zip_file_object, title):
        modload_obj = zip_file_object.open('csv/modloads.csv')
        modload_data = modload_obj.read()
        modload_obj.close()
        modload_io = StringIO.StringIO(modload_data)
        modload_csv = csv.DictReader(modload_io)
        try:
            while 1:
                modloads = modload_csv.next()
                md5 = modloads['Md5']
                ml = {}
                ml['Action'] = modloads['ActionTypeDesc']
                ml['Timestamp'] = modloads['Timestamp']
                ml['Path'] = modloads['Path']
                self._add_result(title, md5, ml)
        except Exception as e:
            pass


    def show_filemods(self, zip_file_object, title):
        filemod_obj = zip_file_object.open('csv/filemods.csv')
        filemod_data = filemod_obj.read()
        filemod_obj.close()
        filemod_io = StringIO.StringIO(filemod_data)
        filemod_csv = csv.DictReader(filemod_io)
        try:
            while 1:
                filemods = filemod_csv.next()
                fm = {}
                path = filemods['Path']
                fm['Action'] = filemods['ActionTypeDesc']
                fm['Timestamp'] = filemods['Timestamp']
                self._add_result(title, path, fm)
        except Exception as e:
            pass

    def show_regmods(self, zip_file_object, title):
        regmod_obj = zip_file_object.open('csv/regmods.csv')
        regmod_data = regmod_obj.read()
        regmod_obj.close()
        regmod_io = StringIO.StringIO(regmod_data)
        regmod_csv = csv.DictReader(regmod_io)
        try:
            while 1:
                regmods = regmod_csv.next()
                fm = {}
                action = regmods['ActionTypeDesc']
                fm['Timestamp'] = regmods['Timestamp']
                fm['Path'] = regmods['Path']
                self._add_result(title, action, fm)
        except Exception as e:
            pass

    def show_netconns(self, zip_file_object, title):
        netconn_obj = zip_file_object.open('csv/netconn.csv')
        netconn_data = netconn_obj.read()
        netconn_obj.close()
        netconn_io = StringIO.StringIO(netconn_data)
        netconn_csv = csv.DictReader(netconn_io)
        try:
            while 1:
                netconns = netconn_csv.next()
                nc = {}
                IP = netconns['Ip']
                nc['Timestamp'] = netconns['Timestamp']
                nc['Domain'] = netconns['Domain']
                nc['Port'] = netconns['Port']
                nc['Protocol'] = netconns['Protocol']
                nc['Direction'] = netconns['Direction']
                self._add_result(title, IP, nc)
        except Exception as e:
            pass


    def show_childprocs(self, zip_file_object, cb, title, hostname, pid):
        childproc_md5s = set()
        childproc_obj = zip_file_object.open('json/process.json')
        childproc_data = json.loads(childproc_obj.read())
        childproc_obj.close()

        child_ids = []
        if 'childproc_complete' in childproc_data['process']:
            cp_data = {}
            for cp in childproc_data['process']['childproc_complete']:
                cpd = cp.split('|')

                # Grab the child id and segment_id so we can get its details
                child_pid = cpd[4]
                child_uid = cpd[1].split('-')
                childproc_id = "-".join(child_uid[0:5])
                childproc_segmentid = child_uid[-1].replace('0', '')
                if (childproc_id, childproc_segmentid, child_pid) not in child_ids:
                    child_ids.append((childproc_id, childproc_segmentid, child_pid))

                if child_pid in cp_data:
                    if 'Stop Time' not in cp_data[child_pid]:
                        cp_data[child_pid]['Stop Time'] = cpd[0]
                else:
                    cp_data[child_pid] = {}
                    cp_data[child_pid]['Start Time'] = cpd[0]
                    cp_data[child_pid]['Stop Time'] = ''
                    cp_data[child_pid]['process md5'] = cpd[2]
                    cp_data[child_pid]['process path'] = cpd[3]

            for child_pid, data in cp_data.iteritems():
                cp = {}
                cp['pid'] = child_pid
                child_md5 = data['process md5']
                cp['path'] = data['process path']
                cp['Start Time'] = data['Start Time']
                cp['Stop Time'] = data['Stop Time']
                #childproc_name = os.path.basename(cp['path'])
                #self._info(childproc_name)
                #if childproc_name == cp['path']:
                #    childproc_name = ntpath.basename(cp['path'])
                #childproc_md5s.add((child_md5, childproc_name))
                self._add_result(title, child_md5, cp)

        for child_id in child_ids:
            uid = child_id[0]
            segment_id = child_id[1]
            child_pid = child_id[2]
            
            self.completed_uids.append(uid)

            child_proc_json = cb.process_events(uid, segment_id)
            child_proc_data = {}
            child_proc_data['start time'] = child_proc_json['process']['start']
            child_proc_data['hostname'] = child_proc_json['process']['hostname']
            child_proc_data['username'] = child_proc_json['process']['username']
            child_proc_data['pid'] = child_proc_json['process']['process_pid']
            child_proc_data['ModLoad Count'] = child_proc_json['process']['modload_count']
            child_proc_data['FileMod Count'] = child_proc_json['process']['filemod_count']
            child_proc_data['RegMod Count'] = child_proc_json['process']['regmod_count']
            child_proc_data['NetConn Count'] = child_proc_json['process']['netconn_count']
            child_proc_data['ChildProc Count'] = child_proc_json['process']['childproc_count']
            child_proc_data['CrossProc Count'] = child_proc_json['process']['crossproc_count']

            self._add_result('Child Process Information', child_proc_json['process']['process_name'], child_proc_data)

            child_report = cb.process_report(uid, segment_id)
            child_report_io = StringIO.StringIO(child_report)
            child_zfo = zipfile.ZipFile(child_report_io)

            self.show_modloads(child_zfo, 'Module loads for child process of ' + hostname + '/' + str(pid))
            self.show_filemods(child_zfo, 'File Modifications for child process of ' + hostname + '/' + str(pid))
            self.show_regmods(child_zfo, 'Registry Modifications for child process of ' + hostname + '/' + str(pid))
            self.show_netconns(child_zfo, 'Network Connections for child process of ' + hostname + '/' + str(pid))
            self.show_childprocs(child_zfo, cb, 'Child Proesses for child process of ' + hostname + '/' + str(pid), hostname, child_pid)

 
        #for child_md5, child_name in childproc_md5s:
        #    self._info("Child MD5: %s" % child_md5)
        #    self._info("Child Name: %s" % child_name)
        #    self._info("Parent MD5: %s" % self.obj.md5)
        #    if child_md5 != self.obj.md5:
        #        details = get_sample_details(child_md5, CB_CRITS_USER, 'json')
        #        if details[0] == 'error.html':
        #            self._info("Sample not found")
        #            try:
        #                sample = handle_file(
        #                    child_name,
        #                    '',
        #                    self.obj.source,
        #                    md5_digest=child_md5,
        #                    campaign=self.obj.campaign,
        #                    user=CB_CRITS_USER,
        #                    related_md5=self.obj.md5,
        #                    related_id=self.obj.id,
        #                    related_type='Sample',
        #                    method="Child process from Carbon Black",
        #                    bucket_list=self.obj.bucket_list)
        #                if child_md5 != sample:
        #                    self._error("Error adding child md5")
        #                else:
        #                    self._info("I think it worked")
        #            except Exception as e:
        #                self._error(traceback.format_exc())


