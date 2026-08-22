/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package component

import (
	"context"
	"path"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type callbackSet struct {
	pattern     string
	newCallback func(netlink.Link)
	delCallback func(netlink.Link)
}

type InterfaceManager struct {
	closed    context.Context
	close     context.CancelFunc
	mu        sync.Mutex
	callbacks []callbackSet
	upLinks   map[string]bool
}

func NewInterfaceManager() *InterfaceManager {
	closed, toClose := context.WithCancel(context.Background())
	mgr := &InterfaceManager{
		callbacks: make([]callbackSet, 0),
		closed:    closed,
		close:     toClose,
		upLinks:   make(map[string]bool),
	}

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	subscribed := true
	if e := netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			log.Debug("LinkSubscribe:", err)
		},
		ListExisting: true,
	}); e != nil {
		subscribed = false
		log.Errorf("Failed to subscribe to link updates: %v", e)
	}

	go mgr.monitor(ch, done, subscribed)
	return mgr
}

func (m *InterfaceManager) monitor(ch <-chan netlink.LinkUpdate, done chan struct{}, subscribed bool) {
	for {
		select {
		case <-m.closed.Done():
			close(done)
			// A successful subscription needs a receiver after this loop
			// leaves: closing done makes the library close its netlink socket,
			// but a subscription goroutine already blocked sending an update
			// (link teardown itself bursts RTM_NEWLINK/DELLINK events) never
			// regains one and leaks. The drain ends when the socket close
			// unblocks the sender and the library closes ch. A failed
			// subscription has no sender, so nobody would ever close ch.
			if subscribed {
				go func() {
					for range ch {
					}
				}()
			}
			return
		case update := <-ch:
			ifName := update.Link.Attrs().Name

			switch update.Header.Type {
			case unix.RTM_NEWLINK:
				m.mu.Lock()
				_, exists := m.upLinks[ifName]
				if exists {
					m.mu.Unlock()
					continue
				}
				m.upLinks[ifName] = true
				for _, callback := range m.callbacks {
					matched, err := path.Match(callback.pattern, ifName)
					if err != nil || !matched {
						continue
					}
					if callback.newCallback != nil {
						callback.newCallback(update.Link)
					}
				}
				m.mu.Unlock()

			case unix.RTM_DELLINK:
				m.mu.Lock()
				delete(m.upLinks, ifName)
				for _, callback := range m.callbacks {
					matched, err := path.Match(callback.pattern, ifName)
					if err != nil || !matched {
						continue
					}
					if callback.delCallback != nil {
						callback.delCallback(update.Link)
					}
				}
				m.mu.Unlock()
			}
		}
	}
}

func (m *InterfaceManager) RegisterWithPattern(pattern string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	links, err := netlink.LinkList()
	if err == nil {
		for _, link := range links {
			ifname := link.Attrs().Name
			if matched, err := path.Match(pattern, ifname); err == nil && matched {
				m.upLinks[ifname] = true

				if initCallback != nil {
					initCallback(link)
				}
			}
		}
	} else {
		log.Errorf("Failed to get link list: %v", err)
	}

	m.callbacks = append(m.callbacks, callbackSet{
		pattern:     pattern,
		newCallback: newCallback,
		delCallback: delCallback,
	})
}

func (m *InterfaceManager) Register(ifname string, initCallback func(netlink.Link), newCallback func(netlink.Link), delCallback func(netlink.Link)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	link, err := netlink.LinkByName(ifname)
	if err == nil {
		m.upLinks[ifname] = true

		if initCallback != nil {
			initCallback(link)
		}
	}

	m.callbacks = append(m.callbacks, callbackSet{
		pattern:     ifname,
		newCallback: newCallback,
		delCallback: delCallback,
	})
}

// Close cancels the context to stop the monitor goroutine
func (m *InterfaceManager) Close() error {
	m.close()
	return nil
}
