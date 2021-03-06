/*
 * Copyright (c) 2016, Luc Yriarte
 * BSD License <http://www.opensource.org/licenses/bsd-license.php>
 * 
 * Author:
 * Luc Yriarte <luc.yriarte@thingagora.org>
 */

#include <Python.h>
#include <stdlib.h>
#include <stdio.h>

#include "pylwm2m.h"



/* Parses the uri from python into lwm2m_uri_t
 * returns -1 on error
 * return 0 on succes.
 */

static int
pylwm2m_parse_uri_str(const char* uriStr, lwm2m_uri_t* uri) {
    if (!uriStr) {
        PyErr_SetString(PyExc_ValueError, "URI is empty");
        return -1;
    }

    if (!lwm2m_stringToUri(uriStr, strlen(uriStr), uri)) {
        PyErr_Format(PyExc_ValueError, "Not a valid URI: %s", uriStr);
        return -1;
    }

    return 0;
}

static pylwm2m_result_t*
new_result_ptr(PyObject* cb, PyObject* cb_data)
{
    pylwm2m_result_t* result_ptr = (pylwm2m_result_t *) malloc(sizeof(struct _pylwm2m_result_));
    if (result_ptr == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    result_ptr->resultCb = cb;
    result_ptr->resultData = cb_data;

    Py_XINCREF(cb);
    Py_XINCREF(cb_data);

    return result_ptr;
}

static void
destroy_result_ptr(pylwm2m_result_t* result_ptr)
{
    if (result_ptr == NULL) {
        return;
    }

    Py_XDECREF(result_ptr->resultCb);
    Py_XDECREF(result_ptr->resultData);
    free(result_ptr);
}

static int
result_ptr_needs_free(int result) {
    /* If result == 0 => everying is ok => callback will be called.
     * If result == -1 => Callback has already been called.
     * Everyting else is 'COAP_ERROR_......' in which case the wakaama library
     * destroyed the transaction and will never fire the callback.
     * => free result_ptr in this case.
     */
    return !((result == 0) || (result == -1));
}

/*
 * server callbacks
 */

/* Note:
 * Keep in mind that this function is also referenced in pylwm2m_observe.
 * pylwm2m_observe relies on 'call_result_cb' *NOT* free pylwm2m_result_t
 */
void call_result_cb(uint16_t clientID, lwm2m_uri_t * uriP, int status, lwm2m_media_type_t format, uint8_t * data, int dataLength, void * userData) {
TRACE("%s %hu %p %d %d %p %d %p\n",__FUNCTION__, clientID, uriP, status, format, data, dataLength, userData);	
	pylwm2m_result_t * lwm2mresultP = (pylwm2m_result_t *) userData;
	PyObject *pyresult = NULL;
	char * uriStr = NULL;
	static char uriBuf[URI_BUF_SIZE];
	if (lwm2mresultP && PyCallable_Check(lwm2mresultP->resultCb)) {
		if (prv_lwm2m_uri_dump(uriP, uriBuf)) {
			uriStr = uriBuf;
		}
TRACE("%s callback %p Hsis#iO %hu %s %d %d %s[%d] %d %p\n",__FUNCTION__, lwm2mresultP->resultCb, 
				clientID, uriStr, status, format, data, dataLength, dataLength, lwm2mresultP->resultData);
		pyresult = PyObject_CallFunction(lwm2mresultP->resultCb, "Hsiis#iO", 
				clientID, uriStr, status, format, data, dataLength, dataLength, lwm2mresultP->resultData);
TRACE("%s pyresult: %p\n",__FUNCTION__,pyresult);
		Py_XDECREF(pyresult);
	}
}

void result_cb_wrapper(uint16_t clientID, lwm2m_uri_t * uriP, int status, lwm2m_media_type_t format, uint8_t * data, int dataLength, void * userData) {
TRACE("%s %hu %p %d %d %p %d %p\n",__FUNCTION__, clientID, uriP, status, format, data, dataLength, userData);	
	pylwm2m_result_t * lwm2mresultP = (pylwm2m_result_t *) userData;
	call_result_cb(clientID, uriP, status, format, data, dataLength, userData);
    destroy_result_ptr(lwm2mresultP);
}

/*
 * lwm2m server API wrapper
 */ 

PyObject * pylwm2m_set_monitoring_callback(PyObject *self, PyObject *args) {
TRACE("%s %p %p\n",__FUNCTION__, self, args);
	pylwm2m_context_t * pylwm2mH = NULL;
	PyObject *pylwm2mHCap = NULL;
	PyObject *resultCb = NULL;
	PyObject *resultData = NULL;
	if (!PyArg_ParseTuple(args, "OOO", &pylwm2mHCap, &resultCb, &resultData)) {
		return NULL;
	}
	pylwm2mH = PyCapsule_GetPointer(pylwm2mHCap, NULL);
	pylwm2mH->monitoringResult.resultCb = resultCb;
	pylwm2mH->monitoringResult.resultData = resultData;
	Py_XINCREF(pylwm2mH->monitoringResult.resultCb);
	Py_XINCREF(pylwm2mH->monitoringResult.resultData);
TRACE("lwm2m_set_monitoring_callback %p %p %p\n",pylwm2mH->lwm2mH, call_result_cb, (void *)&(pylwm2mH->monitoringResult));
	lwm2m_set_monitoring_callback(pylwm2mH->lwm2mH, call_result_cb, (void *)&(pylwm2mH->monitoringResult));
	return Py_None;
}

/* A few defines to get hide the funny typecasts. */
#define LWM2M_FIND_CLIENT(cl_list, client_id) (lwm2m_client_t*) lwm2m_list_find((lwm2m_list_t*) cl_list, client_id)

static PyObject*
pylwm2m_get_client_info_objects(lwm2m_client_t* client)
{
    PyObject* item = NULL;

    lwm2m_client_object_t* object;
    lwm2m_list_t* instance;

    PyObject* result = PyList_New(0);
    if (result == NULL) {
        return NULL;
    }

    for (object = client->objectList; object; object = object->next) {
        for (instance = object->instanceList; instance; instance = instance->next) {
            if ((item = Py_BuildValue("(HH)", object->id, instance->id)) == NULL) {
                Py_DECREF(result);
                return NULL;
            }

            if (PyList_Append(result, item) == -1) {
                Py_DECREF(result);
                return NULL;
            }

            Py_DECREF(item);
        }
    }

    return result;
}

PyObject*
pylwm2m_get_client_info(PyObject* self, PyObject* args)
{
    pylwm2m_context_t* context;
    lwm2m_client_t* client;

    PyObject* py_context;
    uint16_t client_id;

    if (!PyArg_ParseTuple(args, "OH", &py_context, &client_id)) {
        return NULL;
    }

    if ((context = PyCapsule_GetPointer(py_context, NULL)) == NULL) {
        return NULL;
    }

    client = LWM2M_FIND_CLIENT(context->lwm2mH->clientList, client_id);
    if (client == NULL) {
        return PyErr_Format(PyExc_ValueError, "Unknown client_id");
    }

    PyObject* item = NULL;

    PyObject* result = PyDict_New();
    if (result == NULL) {
        return NULL;
    }

    /* Add the name of the client to the result dict. */
    if ((item = PyString_FromString(client->name)) == NULL) {
        goto Fail;
    }

    if (PyDict_SetItemString(result, "name", item) == -1) {
        goto Fail;
    }

    /* Get the objects and add them to the result. */
    if ((item = pylwm2m_get_client_info_objects(client)) == NULL) {
        goto Fail;
    }

    if (PyDict_SetItemString(result, "objects", item) == -1) {
        goto Fail;
    }

    /* Add the current session handle to the result dict. */
    item = (PyObject*) client->sessionH;
    if (item != NULL) {
        if (PyDict_SetItemString(result, "session", item) == -1) {
            goto Fail;
        }
    }

    /* Add the flag if json is supported or not. */
    if ((item = PyBool_FromLong(client->supportJSON)) == NULL) {
        goto Fail;
    }

    if (PyDict_SetItemString(result, "json_support", item) == -1) {
        goto Fail;
    }

    /* Add the current lifetime. */
    if ((item = PyLong_FromUnsignedLong(client->lifetime)) == NULL) {
        goto Fail;
    }

    if (PyDict_SetItemString(result, "lifetime", item) == -1) {
        goto Fail;
    }

    return result;

Fail:
    Py_XDECREF(result);
    Py_XDECREF(item);
    return NULL;
}


PyObject * pylwm2m_dm_read(PyObject *self, PyObject *args) {
TRACE("%s %p %p\n",__FUNCTION__, self, args);
	pylwm2m_context_t * pylwm2mH = NULL;
	PyObject *pylwm2mHCap = NULL;
	uint16_t clientID = (uint16_t) -1;
	const char *uriStr = NULL;
	lwm2m_uri_t uri;
	PyObject *resultCb = NULL;
	PyObject *resultData = NULL;
	pylwm2m_result_t * lwm2mresultP = NULL;
	int result = -1;
	if (!PyArg_ParseTuple(args, "OHsOO", &pylwm2mHCap, &clientID, &uriStr, &resultCb, &resultData)) {
        return NULL;
    }

    if (pylwm2m_parse_uri_str(uriStr, &uri) == -1) {
        return NULL;
    }

    if ((lwm2mresultP = new_result_ptr(resultCb, resultData)) == NULL) {
        return NULL;
    }

	pylwm2mH = PyCapsule_GetPointer(pylwm2mHCap, NULL);

TRACE("lwm2m_dm_read %p %hu %p %p %p\n",pylwm2mH->lwm2mH, clientID, &uri, result_cb_wrapper, lwm2mresultP);
	result = lwm2m_dm_read(pylwm2mH->lwm2mH, clientID, &uri, result_cb_wrapper, lwm2mresultP);
TRACE("lwm2m_dm_read result: %d\n", result);

    if (result_ptr_needs_free(result)) {
        destroy_result_ptr(lwm2mresultP);
    }

	return Py_BuildValue("i", result);
}

PyObject * pylwm2m_dm_write(PyObject *self, PyObject *args) {
TRACE("%s %p %p\n",__FUNCTION__, self, args);
	pylwm2m_context_t * pylwm2mH = NULL;
	PyObject *pylwm2mHCap = NULL;
	uint16_t clientID = (uint16_t) -1;
	const char *uriStr = NULL;
	lwm2m_uri_t uri;
	lwm2m_media_type_t format;
	uint8_t *buffer = NULL;
	int length = -1;
	PyObject *resultCb = NULL;
	PyObject *resultData = NULL;
	pylwm2m_result_t * lwm2mresultP = NULL;
	int result = -1;
	if (!PyArg_ParseTuple(args, "OHsis#iOO", &pylwm2mHCap, &clientID, &uriStr, &format, &buffer, &length, &length, &resultCb, &resultData)) {
        return NULL;
    }

    if (pylwm2m_parse_uri_str(uriStr, &uri) == -1) {
        return NULL;
    }

    if ((lwm2mresultP = new_result_ptr(resultCb, resultData)) == NULL) {
        return NULL;
    }

	pylwm2mH = PyCapsule_GetPointer(pylwm2mHCap, NULL);

TRACE("lwm2m_dm_write %p %hu %p %d %p %d %p %p\n",pylwm2mH->lwm2mH, clientID, &uri, format, buffer, length, result_cb_wrapper, lwm2mresultP);
	result = lwm2m_dm_write(pylwm2mH->lwm2mH, clientID, &uri, format, buffer, length, result_cb_wrapper, lwm2mresultP);
TRACE("lwm2m_dm_write result: %d\n", result);

    if (result_ptr_needs_free(result)) {
        destroy_result_ptr(lwm2mresultP);
    }

	return Py_BuildValue("i", result);
}

PyObject * pylwm2m_dm_execute(PyObject *self, PyObject *args) {
TRACE("%s %p %p\n",__FUNCTION__, self, args);
	pylwm2m_context_t * pylwm2mH = NULL;
	PyObject *pylwm2mHCap = NULL;
	uint16_t clientID = (uint16_t) -1;
	const char *uriStr = NULL;
	lwm2m_uri_t uri;
	lwm2m_media_type_t format;
	uint8_t *buffer = NULL;
	int length = -1;
	PyObject *resultCb = NULL;
	PyObject *resultData = NULL;
	pylwm2m_result_t * lwm2mresultP = NULL;
	int result = -1;
	if (!PyArg_ParseTuple(args, "OHsis#iOO", &pylwm2mHCap, &clientID, &uriStr, &format, &buffer, &length, &length, &resultCb, &resultData)) {
        return NULL;
    }

    if (pylwm2m_parse_uri_str(uriStr, &uri) == -1) {
        return NULL;
    }
    if ((lwm2mresultP = new_result_ptr(resultCb, resultData)) == NULL) {
        return NULL;
    }

	pylwm2mH = PyCapsule_GetPointer(pylwm2mHCap, NULL);

TRACE("lwm2m_dm_execute %p %hu %p %d %p %d %p %p\n",pylwm2mH->lwm2mH, clientID, &uri, format, buffer, length, result_cb_wrapper, lwm2mresultP);
	result = lwm2m_dm_execute(pylwm2mH->lwm2mH, clientID, &uri, format, buffer, length, result_cb_wrapper, lwm2mresultP);
TRACE("lwm2m_dm_execute result: %d\n", result);

    if (result_ptr_needs_free(result)) {
        destroy_result_ptr(lwm2mresultP);
    }

	return Py_BuildValue("i", result);
}

PyObject * pylwm2m_dm_create(PyObject *self, PyObject *args) {
TRACE("%s %p %p\n",__FUNCTION__, self, args);
	pylwm2m_context_t * pylwm2mH = NULL;
	PyObject *pylwm2mHCap = NULL;
	uint16_t clientID = (uint16_t) -1;
	const char *uriStr = NULL;
	lwm2m_uri_t uri;
	lwm2m_media_type_t format;
	uint8_t *buffer = NULL;
	int length = -1;
	PyObject *resultCb = NULL;
	PyObject *resultData = NULL;
	pylwm2m_result_t * lwm2mresultP = NULL;
	int result = -1;
	if (!PyArg_ParseTuple(args, "OHsis#iOO", &pylwm2mHCap, &clientID, &uriStr, &format, &buffer, &length, &length, &resultCb, &resultData)) {
        return NULL;
    }

    if (pylwm2m_parse_uri_str(uriStr, &uri) == -1) {
        return NULL;
    }
    if ((lwm2mresultP = new_result_ptr(resultCb, resultData)) == NULL) {
        return NULL;
    }

	pylwm2mH = PyCapsule_GetPointer(pylwm2mHCap, NULL);

TRACE("lwm2m_dm_create %p %hu %p %d %p %d %p %p\n",pylwm2mH->lwm2mH, clientID, &uri, format, buffer, length, result_cb_wrapper, lwm2mresultP);
	result = lwm2m_dm_create(pylwm2mH->lwm2mH, clientID, &uri, format, buffer, length, result_cb_wrapper, lwm2mresultP);
TRACE("lwm2m_dm_create result: %d\n", result);

    if (result_ptr_needs_free(result)) {
        destroy_result_ptr(lwm2mresultP);
    }

	return Py_BuildValue("i", result);
}

PyObject * pylwm2m_dm_delete(PyObject *self, PyObject *args) {
TRACE("%s %p %p\n",__FUNCTION__, self, args);
	pylwm2m_context_t * pylwm2mH = NULL;
	PyObject *pylwm2mHCap = NULL;
	uint16_t clientID = (uint16_t) -1;
	const char *uriStr = NULL;
	lwm2m_uri_t uri;
	PyObject *resultCb = NULL;
	PyObject *resultData = NULL;
	pylwm2m_result_t * lwm2mresultP = NULL;
	int result = -1;
	if (!PyArg_ParseTuple(args, "OHsOO", &pylwm2mHCap, &clientID, &uriStr, &resultCb, &resultData)) {
        return NULL;
    }

    if (pylwm2m_parse_uri_str(uriStr, &uri) == -1) {
        return NULL;
    }

    if ((lwm2mresultP = new_result_ptr(resultCb, resultData)) == NULL) {
        return NULL;
    }

	pylwm2mH = PyCapsule_GetPointer(pylwm2mHCap, NULL);

TRACE("lwm2m_dm_delete %p %hu %p %p %p\n",pylwm2mH->lwm2mH, clientID, &uri, result_cb_wrapper, lwm2mresultP);
	result = lwm2m_dm_delete(pylwm2mH->lwm2mH, clientID, &uri, result_cb_wrapper, lwm2mresultP);
TRACE("lwm2m_dm_delete result: %d\n", result);

    if (result_ptr_needs_free(result)) {
        destroy_result_ptr(lwm2mresultP);
    }

	return Py_BuildValue("i", result);
}

static int
construct_attributes_from_dict(lwm2m_attributes_t* attributes, PyObject* py_attributes)
{
    if (!PyDict_Check(py_attributes)) {
        PyErr_Format(PyExc_ValueError, "attributes must be a dictionary");
        return -1;
    }


    memset(attributes, 0, sizeof(lwm2m_attributes_t));

    PyObject* val = NULL;

    /* Go over the fields and set/clear if they are present.
     * To clear a field use None.
     */

    val = PyDict_GetItemString(py_attributes, "min_period");
    if (val != NULL) {
        if (val == Py_None) {
            attributes->toClear |= LWM2M_ATTR_FLAG_MIN_PERIOD;
        }
        else {
            unsigned long min_period = PyLong_AsUnsignedLong(val);
            if (PyErr_Occurred()) {
                return -1;
            }

            if (min_period > UINT32_MAX) {
                PyErr_Format(PyExc_ValueError, "min_period too big");
                return -1;
            }

            attributes->toSet |= LWM2M_ATTR_FLAG_MIN_PERIOD;
            attributes->minPeriod = (uint32_t) min_period;
        }
    }

    val = PyDict_GetItemString(py_attributes, "max_period");
    if (val != NULL) {
        if (val == Py_None) {
            attributes->toClear |= LWM2M_ATTR_FLAG_MAX_PERIOD;
        }
        else {
            unsigned long max_period = PyLong_AsUnsignedLong(val);
            if (PyErr_Occurred()) {
                return -1;
            }

            if (max_period > UINT32_MAX) {
                PyErr_Format(PyExc_ValueError, "max_period too big");
                return -1;
            }

            attributes->toSet |= LWM2M_ATTR_FLAG_MAX_PERIOD;
            attributes->maxPeriod = (uint32_t) max_period;
        }
    }

    val = PyDict_GetItemString(py_attributes, "greater_than");
    if (val != NULL) {
        if (val == Py_None) {
            attributes->toClear |= LWM2M_ATTR_FLAG_GREATER_THAN;
        }
        else {
            double greater_than = PyFloat_AsDouble(val);
            if (PyErr_Occurred()) {
                return -1;
            }

            attributes->toSet |= LWM2M_ATTR_FLAG_GREATER_THAN;
            attributes->greaterThan = greater_than;
        }
    }

    val = PyDict_GetItemString(py_attributes, "less_than");
    if (val != NULL) {
        if (val == Py_None) {
            attributes->toClear |= LWM2M_ATTR_FLAG_LESS_THAN;
        }
        else {
            double less_than = PyFloat_AsDouble(val);
            if (PyErr_Occurred()) {
                return -1;
            }

            attributes->toSet |= LWM2M_ATTR_FLAG_LESS_THAN;
            attributes->lessThan = less_than;
        }
    }

    val = PyDict_GetItemString(py_attributes, "step");
    if (val != NULL) {
        if (val == Py_None) {
            attributes->toClear |= LWM2M_ATTR_FLAG_STEP;
        }
        else {
            double step = PyFloat_AsDouble(val);
            if (PyErr_Occurred()) {
                return -1;
            }

            attributes->toSet |= LWM2M_ATTR_FLAG_STEP;
            attributes->step = step;
        }
    }

    return 0;
}

PyObject*
pylwm2m_dm_write_attributes(PyObject* self, PyObject* args) {
    int result = 0;
    pylwm2m_context_t* context = NULL;
    lwm2m_uri_t uri;
    lwm2m_attributes_t attributes;
    pylwm2m_result_t* result_ptr = NULL;

    PyObject* py_context;
    uint16_t client_id = 0;
    const char* uri_str = NULL;
    PyObject* py_attributes = NULL;
    PyObject* result_cb = NULL;
    PyObject* result_cb_data = NULL;

    if (!PyArg_ParseTuple(args, "OHsOOO", &py_context, &client_id, &uri_str, &py_attributes, &result_cb, &result_cb_data)) {
        return NULL;
    }

    if ((context = PyCapsule_GetPointer(py_context, NULL)) == NULL) {
        return NULL;
    }

    if (construct_attributes_from_dict(&attributes, py_attributes) == -1) {
        return NULL;
    }

    if (pylwm2m_parse_uri_str(uri_str, &uri) == -1) {
        return NULL;
    }

    if ((result_ptr = new_result_ptr(result_cb, result_cb_data)) == NULL) {
        return NULL;
    }

    result = lwm2m_dm_write_attributes(
        context->lwm2mH,
        client_id,
        &uri,
        &attributes,
        result_cb_wrapper,
        result_ptr);

    if (result_ptr_needs_free(result)) {
        destroy_result_ptr(result_ptr);
    }

    return Py_BuildValue("i", result);
}

PyObject * pylwm2m_observe(PyObject *self, PyObject *args)
{
    int result = 0;
    pylwm2m_context_t* context = NULL;
    lwm2m_uri_t uri;
    pylwm2m_result_t* result_ptr = NULL;

    PyObject* py_context;
    uint16_t client_id = 0;
    const char* uri_str = NULL;
    PyObject* result_cb = NULL;
    PyObject* result_cb_data = NULL;

    if (!PyArg_ParseTuple(args, "OHsOO", &py_context, &client_id, &uri_str, &result_cb, &result_cb_data)) {
        return NULL;
    }

    if ((context = PyCapsule_GetPointer(py_context, NULL)) == NULL) {
        return NULL;
    }

    if (pylwm2m_parse_uri_str(uri_str, &uri) == -1) {
        return NULL;
    }

    if ((result_ptr = new_result_ptr(result_cb, result_cb_data)) == NULL) {
        return NULL;
    }

    /* The thing is this:
     *  'result_cb' will be called:
     *  1) When the response of the 'observe' comes back. For example 2.05/4.04/....
     *  2) When a notification comes in.
     * => pylwm2m_result_t must be kept until the observation is canceled.
     * Right now I don't know how to free it correctly => Memory Leak !!!!!!
     */

    result = lwm2m_observe(
        context->lwm2mH,
        client_id,
        &uri,
        call_result_cb,
        result_ptr);

    if (result_ptr_needs_free(result)) {
        destroy_result_ptr(result_ptr);
    }

    return Py_BuildValue("i", result);
}

PyObject* pylwm2m_observe_cancel(PyObject *self, PyObject *args)
{
    int result = 0;
    pylwm2m_context_t* context = NULL;
    lwm2m_uri_t uri;
    pylwm2m_result_t* result_ptr = NULL;

    PyObject* py_context;
    uint16_t client_id = 0;
    const char* uri_str = NULL;
    PyObject* result_cb = NULL;
    PyObject* result_cb_data = NULL;

    if (!PyArg_ParseTuple(args, "OHsOO", &py_context, &client_id, &uri_str, &result_cb, &result_cb_data)) {
        return NULL;
    }

    if ((context = PyCapsule_GetPointer(py_context, NULL)) == NULL) {
        return NULL;
    }

    if (pylwm2m_parse_uri_str(uri_str, &uri) == -1) {
        return NULL;
    }

    if ((result_ptr = new_result_ptr(result_cb, result_cb_data)) == NULL) {
        return NULL;
    }

    result = lwm2m_observe_cancel(
        context->lwm2mH,
        client_id,
        &uri,
        result_cb_wrapper,
        result_ptr);

    if (result_ptr_needs_free(result)) {
        destroy_result_ptr(result_ptr);
    }

    return Py_BuildValue("i", result);
}
